//! A stand-in Coldcard on the `ckcc` simulator socket, to check `catcard_usb::ckcc`
//! against the real host library as a black box. Not the firmware: it answers from
//! canned values and logs every request.
//!
//! ```sh
//! cargo run -p catcard-usb --example ckcc_sim &
//! ckcc -x version      # the host tool, talking to this over /tmp/ckcc-simulator.sock
//! ```

use std::os::unix::net::UnixDatagram;

use catcard_usb::ckcc::{self, Link, Request, Rx, RxEvent, Tx, reply};

const SOCK: &str = "/tmp/ckcc-simulator.sock";

/// BIP-32 test vector 1's master xpub: public, and anything will do.
const XPUB: &str = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";

/// Its private key, for `mitm`.
const MASTER_KEY: [u8; 32] = [
    0xe8, 0xf3, 0x2e, 0x72, 0x3d, 0xec, 0xf4, 0x05, 0x1a, 0xef, 0xac, 0x8e, 0x2c, 0x93, 0xc9, 0xc5,
    0xb2, 0x14, 0x31, 0x38, 0x17, 0xcd, 0xb0, 0x1a, 0x14, 0x94, 0xb9, 0x17, 0xc8, 0x43, 0x6b, 0x35,
];

fn main() {
    let _ = std::fs::remove_file(SOCK);
    let sock = UnixDatagram::bind(SOCK).expect("bind");
    eprintln!("sim: listening on {SOCK}");
    let mut link = Link::new();
    let mut rx = Rx::new();
    let mut buf = vec![0u8; ckcc::MAX_WIRE_LEN + 64];
    let mut upload = ckcc::Upload::new();
    let mut staged = vec![0u8; 4 << 20];
    let mut report = [0u8; 256];
    let mut polls = 0u32;
    loop {
        let (n, from) = sock.recv_from(&mut report).expect("recv");
        let Some(from) = from.as_pathname().map(|p| p.to_path_buf()) else {
            eprintln!("sim: unnamed peer");
            continue;
        };
        // macOS hands back the peer's path one byte short (the length it reports leaves
        // off the last character); put it back when the short one does not exist.
        let from = if from.exists() {
            from
        } else {
            let mut s = from.into_os_string();
            s.push("k");
            std::path::PathBuf::from(s)
        };
        let ev = match rx.feed(&report[..n], &mut buf, link.max_wire()) {
            Ok(e) => e,
            Err(f) => {
                eprintln!("sim: fram {}", f.reason());
                link.failed();
                let n = reply::fram(&mut buf, f.reason()).unwrap();
                send(&sock, &from, &buf[..n], false);
                continue;
            }
        };
        let (len, enc) = match ev {
            RxEvent::More => continue,
            RxEvent::Reset => {
                eprintln!("sim: resync");
                upload.clear();
                continue;
            }
            RxEvent::Message { len, encrypted } => (len, encrypted),
        };
        let plen = match link.open(&mut buf, len, enc) {
            Ok(p) => p,
            Err(f) => {
                eprintln!("sim: open failed {}", f.reason());
                link.failed();
                let n = reply::fram(&mut buf, f.reason()).unwrap();
                send(&sock, &from, &buf[..n], false);
                continue;
            }
        };
        let msg = buf[..plen].to_vec();
        let mut out = vec![0u8; ckcc::MAX_WIRE_LEN + 64];
        let req = Request::parse(&msg);
        let shown = match &req {
            Ok(Ok(Request::Upload {
                offset,
                total,
                data,
            })) => format!("upld off={offset} total={total} n={}", data.len()),
            Ok(Ok(r)) => format!("{r:?}").chars().take(200).collect(),
            other => format!("{other:?}"),
        };
        eprintln!(
            "sim: {} enc={} v={:?} len={} {}",
            String::from_utf8_lossy(&msg[..4]),
            enc,
            link.version(),
            plen,
            shown
        );
        let n = match req {
            Err(f) => reply::fram(&mut out, f.reason()).unwrap(),
            Ok(Err(e)) => reply::err(&mut out, e.text()).unwrap(),
            Ok(Ok(req)) => match req {
                Request::Version => reply::asci(
                    &mut out,
                    b"2026-09-27\n7.0.0\n3.0.0\n20260927000000-v7.0.0\nmk4",
                )
                .unwrap(),
                Request::Ping(d) => reply::biny(&mut out, d).unwrap(),
                Request::Ncry { version, host_pub } => {
                    let scalar = [0x11u8; 32];
                    match link.handshake(version, host_pub, &scalar) {
                        Ok(dev) => {
                            reply::mypb(&mut out, &dev, 0x0F05_6943, XPUB.as_bytes()).unwrap()
                        }
                        Err(e) => reply::err(&mut out, &format!("{e:?}")).unwrap(),
                    }
                }
                Request::Xpub(_) => reply::asci(&mut out, XPUB.as_bytes()).unwrap(),
                Request::Show { .. } => reply::asci(&mut out, b"bc1qfakeaddress").unwrap(),
                Request::Chain => reply::asci(&mut out, b"BTC").unwrap(),
                Request::Upload {
                    offset,
                    total,
                    data,
                } => match upload.check(offset, total, data.len(), staged.len() as u32) {
                    Ok(()) => {
                        let at = offset as usize;
                        staged[at..at + data.len()].copy_from_slice(data);
                        upload.accept(offset, total, data);
                        reply::int1(&mut out, offset).unwrap()
                    }
                    Err(e) => reply::err(&mut out, e).unwrap(),
                },
                Request::Sha => reply::biny(&mut out, &upload.digest()).unwrap(),
                Request::Mitm => {
                    let key = *link.session_key().expect("no session");
                    let kw = catcard_wallet::KeyWork::host();
                    let sig = catcard_wallet::message::sign_raw_digest(&key, &MASTER_KEY, &kw)
                        .expect("sign");
                    reply::biny(&mut out, &sig).unwrap()
                }
                // Signing, as a stand-in: "approved" on the second poll, and the result
                // is the upload handed back unchanged.
                Request::SignTx { .. } | Request::SignMsg { .. } => {
                    polls = 0;
                    reply::okay(&mut out).unwrap()
                }
                Request::SignTxPoll => {
                    polls += 1;
                    if polls < 2 {
                        reply::okay(&mut out).unwrap()
                    } else {
                        reply::strx(&mut out, upload.total(), &upload.digest()).unwrap()
                    }
                }
                Request::SignMsgPoll => {
                    polls += 1;
                    if polls < 2 {
                        reply::okay(&mut out).unwrap()
                    } else {
                        reply::smrx(&mut out, b"bc1qfakeaddress", &[0x1f; 65]).unwrap()
                    }
                }
                Request::Download { offset, length, .. } => {
                    let (a, n) = (offset as usize, length as usize);
                    reply::biny(&mut out, &staged[a..a + n]).unwrap()
                }
                _ => reply::err(&mut out, "Unknown cmd").unwrap(),
            },
        };
        let n = if enc {
            link.seal(&mut out, n).expect("seal")
        } else {
            n
        };
        send(&sock, &from, &out[..n], enc);
    }
}

fn send(sock: &UnixDatagram, to: &std::path::Path, msg: &[u8], enc: bool) {
    let mut tx = Tx::new();
    let mut r = [0u8; 64];
    while tx.next(msg, enc, &mut r) {
        if let Err(e) = sock.send_to(&r, to) {
            eprintln!("sim: send to {} failed: {e}", to.display());
            return;
        }
    }
}
