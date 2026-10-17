//! The CCID smart-card reader: the transport that phones can open.
//!
//! The protocol is `catcard_usb::ccid`'s and host-tested there; this is the glue that
//! lives in the USB task. Every CatCard message that arrives in an APDU is dispatched by
//! the same code that dispatches the HID transport's (`usbtask::on_progress`), and the
//! reply is held here and paged back out in `RDR_to_PC_DataBlock`s. Nothing about what
//! a message *does* -- pairing, the host-wallet questions, an upgrade offer -- is
//! decided in this file.
//!
//! # One command at a time
//!
//! CCID is strictly a command followed by its answer, so the reader's OUT endpoint is
//! armed for the next packet only while a command is being received. From the moment
//! one is whole until the last packet of its answer has gone, the endpoint is left
//! un-armed and the host is NAKed -- bulk flow control, costing nothing. The one way a
//! host breaks in is the `ABORT` class request, which drops everything in hand.
//!
//! # The buffer
//!
//! A command is gathered whole into a heap block of [`MESSAGE_MAX`] bytes, taken from
//! the heap the first time a host powers the card on and kept for the session: this
//! transport is always presented, but a device that never sees a phone never pays for
//! it. Without a block the reader cannot take a command and says so once in the log;
//! the host's read times out, which is what a reader with no card in it looks like.

use core::ops::Range;

use catcard_usb::ccid::apdu::{self, Le, Paged};
use catcard_usb::ccid::{self, Header, MAX_PACKET, MESSAGE_MAX, Outcome, Outgoing, Reader, error};

use crate::heap::Block;
use crate::usbtask::ReplyState;

/// Where the next bytes of a command go.
#[derive(Copy, Clone)]
enum Rx {
    /// Gathering the ten-byte header.
    Header { hdr: [u8; Header::LEN], at: usize },
    /// Gathering `hdr.len` bytes of data into the block.
    Data { hdr: Header, at: usize },
    /// A command longer than the block: its data is read and dropped, then it is
    /// refused. The host sends every byte before it reads the answer, so the answer
    /// has to wait for the last of them.
    Discard { hdr: Header, left: usize },
}

impl Rx {
    const fn fresh() -> Self {
        Rx::Header {
            hdr: [0; Header::LEN],
            at: 0,
        }
    }
}

/// What the task should do after feeding a packet.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub(crate) enum Fed {
    /// More of the command is coming: arm the endpoint for it.
    Receiving,
    /// A command is whole, or an answer is going out: leave the endpoint un-armed.
    Held,
}

/// A whole `XfrBlock`, waiting for the task to dispatch the APDU in the block.
#[derive(Copy, Clone)]
struct Pending {
    seq: u8,
    len: usize,
}

/// How the task answered the APDU it was handed.
pub(crate) enum Answer {
    /// A status word alone: the APDU was not one the card takes.
    Sw(u16),
    /// A chunk that is not the last, taken: `9000`, no data.
    Ack,
    /// The message's reply, to be paged out as the host's `Le` allows.
    Reply(ReplyState, Le),
    /// `GET RESPONSE`: the next page of the reply being paged.
    Page(Le),
}

pub(crate) struct Desk {
    buf: Option<Block>,
    rx: Rx,
    pending: Option<Pending>,
    tx: Option<Outgoing>,
    /// The reply being sent or paged: the body `tx`'s ranges point into.
    held: Option<ReplyState>,
    paged: Option<Paged>,
    reader: Reader,
    /// Chunks back into messages. Public to the task, which resets it when the HID
    /// transport starts a message of its own.
    pub(crate) chain: apdu::Chain,
    /// Whether the OUT endpoint is armed. The HAL arms it itself at every configuration,
    /// so this starts true; the task clears it on each packet and sets it when it arms.
    pub(crate) armed: bool,
    no_memory_said: bool,
}

impl Desk {
    pub(crate) const fn new() -> Self {
        Self {
            buf: None,
            rx: Rx::fresh(),
            pending: None,
            tx: None,
            held: None,
            paged: None,
            reader: Reader::new(),
            chain: apdu::Chain::new(),
            armed: true,
            no_memory_said: false,
        }
    }

    /// As after a bus reset: nothing in hand, the card unpowered, the endpoint armed by
    /// the configuration to come. The block is kept.
    pub(crate) fn reset(&mut self) {
        self.rx = Rx::fresh();
        self.pending = None;
        self.tx = None;
        self.held = None;
        self.paged = None;
        self.reader.reset();
        self.chain.reset();
        self.armed = true;
    }

    /// A control `ABORT` naming `seq`: whatever is in hand is dropped, and the reader
    /// answers only the matching bulk `Abort` until it arrives. A reply being paged goes
    /// too; a message chain open across commands does not -- it was never fed the
    /// dropped command.
    pub(crate) fn control_abort(&mut self, seq: u8) {
        self.rx = Rx::fresh();
        self.pending = None;
        self.tx = None;
        self.held = None;
        self.paged = None;
        self.reader.control_abort(seq);
    }

    /// Whether anything is going on: a packet to send, or a command to dispatch.
    pub(crate) fn busy(&self) -> bool {
        self.tx.is_some() || self.pending.is_some()
    }

    /// Whether a whole `XfrBlock` waits for the task.
    pub(crate) fn dispatch_wanted(&self) -> bool {
        self.pending.is_some()
    }

    /// Whether the reader is between commands with nothing to send, so the endpoint
    /// should be armed if it is not.
    pub(crate) fn idle(&self) -> bool {
        !self.busy()
    }

    /// Take one bulk-OUT packet.
    pub(crate) fn feed(&mut self, pkt: &[u8]) -> Fed {
        if self.busy() {
            // The endpoint was not armed; a packet here is the HAL's re-arm at a
            // reconfiguration racing a command in hand. Nothing to do with it.
            return Fed::Held;
        }
        if self.buf.is_none() {
            self.buf = crate::heap::take(MESSAGE_MAX);
            if self.buf.is_none() {
                if !self.no_memory_said {
                    self.no_memory_said = true;
                    crate::catlog!("ccid: no memory for a command; the reader cannot answer");
                }
                return Fed::Receiving;
            }
        }
        let mut p = pkt;
        while !p.is_empty() {
            match &mut self.rx {
                Rx::Header { hdr, at } => {
                    let n = (Header::LEN - *at).min(p.len());
                    hdr[*at..*at + n].copy_from_slice(&p[..n]);
                    *at += n;
                    p = &p[n..];
                    if *at == Header::LEN {
                        let h = Header::parse(hdr);
                        let len = h.len as usize;
                        if len > ccid::APDU_MAX {
                            self.rx = Rx::Discard { hdr: h, left: len };
                        } else if len == 0 {
                            return self.complete(h);
                        } else {
                            self.rx = Rx::Data { hdr: h, at: 0 };
                        }
                    }
                }
                Rx::Data { hdr, at } => {
                    let len = hdr.len as usize;
                    let n = (len - *at).min(p.len());
                    if let Some(b) = self.buf.as_mut() {
                        b.bytes()[*at..*at + n].copy_from_slice(&p[..n]);
                    }
                    *at += n;
                    p = &p[n..];
                    if *at == len {
                        let h = *hdr;
                        return self.complete(h);
                    }
                }
                Rx::Discard { hdr, left } => {
                    let n = (*left).min(p.len());
                    *left -= n;
                    p = &p[n..];
                    if *left == 0 {
                        let h = *hdr;
                        self.rx = Rx::fresh();
                        let head = self.reader.refused(&h, error::BAD_LENGTH);
                        self.tx = Some(Outgoing::new(head, &[], 0..0, &[]));
                        return Fed::Held;
                    }
                }
            }
        }
        Fed::Receiving
    }

    /// A command is whole: the reader answers it, or hands its APDU to the task.
    fn complete(&mut self, h: Header) -> Fed {
        self.rx = Rx::fresh();
        let Some(buf) = self.buf.as_mut() else {
            return Fed::Receiving;
        };
        match self.reader.command(&h, buf.bytes()) {
            Outcome::Reply { head, data } => {
                let inline = &buf.bytes()[..data.min(16)];
                self.tx = Some(Outgoing::new(head, inline, 0..0, &[]));
            }
            Outcome::Apdu { seq } => {
                self.pending = Some(Pending {
                    seq,
                    len: h.len as usize,
                });
            }
        }
        Fed::Held
    }

    /// The waiting `XfrBlock`'s sequence and APDU length, and the block holding the
    /// APDU, for the task to dispatch. Both are given back through [`answer`] and
    /// [`give_buf`].
    ///
    /// [`answer`]: Self::answer
    /// [`give_buf`]: Self::give_buf
    pub(crate) fn take_pending(&mut self) -> Option<(u8, usize, Block)> {
        let p = self.pending?;
        let buf = self.buf.take()?;
        self.pending = None;
        Some((p.seq, p.len, buf))
    }

    pub(crate) fn give_buf(&mut self, buf: Block) {
        self.buf = Some(buf);
    }

    /// A new message arrived: a reply still being paged is of no further interest.
    pub(crate) fn forget_reply(&mut self) {
        self.held = None;
        self.paged = None;
    }

    /// Start the answer to the `XfrBlock` with sequence `seq` on its way.
    pub(crate) fn answer(&mut self, seq: u8, answer: Answer) {
        match answer {
            Answer::Sw(sw) => self.status_only(seq, sw),
            Answer::Ack => self.status_only(seq, apdu::sw::OK),
            Answer::Reply(r, le) => {
                self.paged = Some(Paged::new(apdu::HEADER + r.len));
                self.held = Some(r);
                self.page(seq, le);
            }
            Answer::Page(le) => {
                if self.paged.is_some() {
                    self.page(seq, le);
                } else {
                    self.status_only(seq, apdu::sw::NOTHING_PENDING);
                }
            }
        }
    }

    fn status_only(&mut self, seq: u8, sw: u16) {
        let head = self.reader.data_block(seq, 2);
        self.tx = Some(Outgoing::new(head, &[], 0..0, &sw.to_be_bytes()));
    }

    /// One page of the held reply: its six-byte header and then its body, as far as
    /// `le` allows, with the status word that says whether more waits.
    fn page(&mut self, seq: u8, le: Le) {
        let (Some(paged), Some(r)) = (self.paged.as_mut(), self.held.as_ref()) else {
            return self.status_only(seq, apdu::sw::NOTHING_PENDING);
        };
        let (range, sw) = paged.page(le);
        let header = apdu::response_header(r.status as u16, r.len);
        let inline = &header[range.start.min(apdu::HEADER)..range.end.min(apdu::HEADER)];
        let body: Range<usize> =
            range.start.saturating_sub(apdu::HEADER)..range.end.saturating_sub(apdu::HEADER);
        let head = self.reader.data_block(seq, range.len() + 2);
        self.tx = Some(Outgoing::new(head, inline, body, &sw.to_be_bytes()));
        if paged.done() {
            self.paged = None;
        }
    }

    /// Compose the next packet of the answer going out, if there is one.
    pub(crate) fn next_packet(&mut self, out: &mut [u8; MAX_PACKET]) -> Option<usize> {
        let tx = self.tx.as_ref()?;
        let body: &[u8] = match self.held.as_mut() {
            Some(r) => {
                let n = r.len;
                &r.body.bytes()[..n]
            }
            None => &[],
        };
        tx.next_packet(body, out)
    }

    /// The composed packet went. True when that was the answer's last: the endpoint
    /// may be armed for the next command.
    pub(crate) fn sent(&mut self) -> bool {
        let Some(tx) = self.tx.as_mut() else {
            return false;
        };
        tx.advance();
        if !tx.done() {
            return false;
        }
        self.tx = None;
        // The body stays only while a later `GET RESPONSE` could still ask for it.
        if self.paged.is_none() {
            self.held = None;
        }
        true
    }
}
