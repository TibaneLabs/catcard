//! A tsslib message broker with no threads and no transport: a mailbox.
//!
//! tsslib's broker-driven parties hand every outgoing message to
//! `MessageReceiver::receive` and register a handler per message type with
//! `MessageBroker::connect`. Here, `receive` only queues the message for the session to
//! seal; inbound messages are handed in with [`Mailbox::deliver`], which calls the
//! type's handler -- or holds the message until the party connects one, since a peer can
//! be a round ahead. Handlers run on the caller's stack, so everything a party does
//! happens inside `deliver` (or inside the party's constructor, for round 1).
//!
//! No lock is held while a handler runs: a handler re-enters the mailbox to send and to
//! connect the next round.
//!
//! **Cycles.** A handler owns its party's state, and that state owns this mailbox. The
//! session breaks the cycle with [`Mailbox::clear`] when it is done or dropped;
//! otherwise the party -- secret share included -- would never be freed.

use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use spin::mutex::SpinMutex;
use tsslib::tss::{BrokerResult, Message, MessageBroker, MessageReceiver};

type Handler = Arc<dyn MessageReceiver + Send + Sync>;

#[derive(Default)]
struct Inner {
    handlers: Vec<(String, Handler)>,
    pending: Vec<Message>,
    outbound: Vec<Message>,
    /// A handler's refusal of a message queued before it connected, which `connect`
    /// cannot return.
    late_error: Option<String>,
}

#[derive(Default)]
pub(crate) struct Mailbox {
    inner: SpinMutex<Inner>,
}

impl Mailbox {
    /// Hand an inbound message to its handler, or hold it for one.
    pub(crate) fn deliver(&self, msg: &Message) -> BrokerResult {
        let handler = {
            let mut inner = self.inner.lock();
            match inner.handlers.iter().find(|(t, _)| *t == msg.typ) {
                Some((_, h)) => Some(Arc::clone(h)),
                None => {
                    inner.pending.push(msg.clone());
                    None
                }
            }
        };
        match handler {
            Some(h) => h.receive(msg),
            None => Ok(()),
        }
    }

    /// What the party has sent since the last call.
    pub(crate) fn take_outbound(&self) -> Vec<Message> {
        core::mem::take(&mut self.inner.lock().outbound)
    }

    pub(crate) fn take_late_error(&self) -> Option<String> {
        self.inner.lock().late_error.take()
    }

    /// Drop every handler and held message: the party's state goes with them.
    pub(crate) fn clear(&self) {
        let (handlers, pending, outbound) = {
            let mut inner = self.inner.lock();
            (
                core::mem::take(&mut inner.handlers),
                core::mem::take(&mut inner.pending),
                core::mem::take(&mut inner.outbound),
            )
        };
        // Dropped here, outside the lock: a handler's drop may drop a party, whose
        // parameters hold this mailbox.
        drop(handlers);
        drop(pending);
        drop(outbound);
    }
}

impl MessageReceiver for Mailbox {
    /// A party sending: queue it for the session.
    fn receive(&self, msg: &Message) -> BrokerResult {
        self.inner.lock().outbound.push(msg.clone());
        Ok(())
    }
}

impl MessageBroker for Mailbox {
    fn connect(&self, typ: &str, dest: Handler) {
        let held = {
            let mut inner = self.inner.lock();
            inner.handlers.retain(|(t, _)| t != typ);
            inner.handlers.push((typ.to_string(), Arc::clone(&dest)));
            let (now, keep): (Vec<_>, Vec<_>) = core::mem::take(&mut inner.pending)
                .into_iter()
                .partition(|m| m.typ == typ);
            inner.pending = keep;
            now
        };
        for msg in held {
            if let Err(e) = dest.receive(&msg) {
                let mut inner = self.inner.lock();
                if inner.late_error.is_none() {
                    inner.late_error = Some(e.to_string());
                }
            }
        }
    }
}
