//! `ncry` — an encrypted channel, paired by a code a person compares on both screens.
//!
//! The framing in the crate root moves messages in the clear. Anything a passive
//! observer on the wire should not see — an `xpub`, an address, a PSBT, the log —
//! travels instead inside an [`Opcode::NcryMsg`](crate::Opcode::NcryMsg) once a session
//! has been set up **and paired**.
//!
//! # Handshake (v2)
//!
//! Commit, then reveal, ephemeral on both sides; the host is the initiator:
//!
//! ```text
//! host   → device   PairCommit,  payload = SHA-256("catcard-pair-v2/commit" ‖ host_pub)
//! device → host     Ok,          payload = device_pub
//! host   → device   PairReveal,  payload = host_pub
//! device → host     Ok,          empty -- BadRequest if host_pub misses the commitment
//! ```
//!
//! Both sides then compute the X25519 shared secret and run it through HKDF-SHA256 with
//! the whole transcript, `commit ‖ device_pub ‖ host_pub`, as the salt: once with
//! [`INFO`] for the two directional keys, once with [`CODE_INFO`] for eight bytes that,
//! taken mod 10^6, are the **pairing code** both screens show as `123 456`.
//!
//! The device asks its user "Pair with this computer?" beside the code; the host tool
//! prints the same code and asks its user. A host whose user says yes sends a sealed
//! [`PairConfirm`](crate::Opcode::PairConfirm). The session is [paired](Session::paired)
//! only when **both** the device user accepted **and** that sealed record authenticated;
//! until then the only sealed record admitted is `PairConfirm` itself ([`Session::admit`]).
//! Either side's refusal, a failed tag, or the prompt's deadline ([`PROMPT_MS`]) ends it.
//!
//! # Why a commitment
//!
//! A relay in the middle runs one handshake with each side. Without the commitment it
//! could wait for the host's key, then grind its own device-facing key offline until its
//! two codes match — 10^6 tries, a moment's work. With it, the host is bound to its key
//! before it has seen anything the relay sends, and the device's key is fresh per
//! handshake, so the relay gets one guess per code a person looks at: one in a million.
//!
//! # What this does and does not defend
//!
//! With the codes compared, it detects an **active relay**: a relayed connection yields a
//! different code on each screen. It is also still what v1 was against a **passive**
//! observer. It does **not** defend against a host that is itself compromised — that host
//! is the other end, and pairing with it is exactly what the person agreed to — nor
//! against a person who accepts without comparing the codes. Nothing is stored on either
//! side: every connection is paired afresh.
//!
//! # Records
//!
//! After the handshake, each direction is a ChaCha20-Poly1305 stream keyed separately,
//! with a per-direction message counter as the nonce. A counter is used once and never
//! reused; the receiver derives the nonce from the count it expects next, so a replayed
//! or reordered record authenticates against the wrong nonce and is rejected. The
//! transport is reliable request/response, so there is no window to track — the next
//! record is the only acceptable one.
//!
//! The bulk firmware-upgrade path is deliberately left in the clear: the image is a
//! public, signed blob whose integrity the signature already guarantees, and it is the
//! one message that streams to staging without being buffered whole, which a per-message
//! seal would break.

use purecrypto::cipher::ChaCha20Poly1305;
use purecrypto::ec::X25519PrivateKey;
use purecrypto::hash::{Digest, Sha256};
use purecrypto::kdf::hkdf;
use zeroize::Zeroize;

/// Length of an X25519 public key, and of an ephemeral scalar.
pub const KEY_LEN: usize = 32;
/// Length of the host's commitment to its public key: one SHA-256.
pub const COMMIT_LEN: usize = 32;
/// Length of the Poly1305 authentication tag a sealed record carries.
pub const TAG_LEN: usize = 16;

/// Bytes added to a plaintext when it is sealed: the authentication tag.
pub const OVERHEAD: usize = TAG_LEN;

/// Largest plaintext a sealed *request* may carry, its two-byte opcode included.
///
/// A request that fits one frame is opened straight off the frame. A longer one -- a
/// chunk of a transaction being uploaded -- spans frames and is gathered whole before
/// anything in it is authenticated, let alone used, so it has to have a bound the device
/// can hold. A kilobyte is sixteen frames and a few hundred milliseconds on this link.
pub const PLAIN_MAX: usize = 1024;

/// Largest sealed request record: [`PLAIN_MAX`] and its tag.
pub const RECORD_MAX: usize = PLAIN_MAX + TAG_LEN;

/// Domain separation for the key schedule. Bump the version suffix for any change that a
/// peer speaking the old scheme would get wrong — a different curve, KDF, cipher or
/// handshake — so the two cannot derive a matching key by accident. `v1` was the
/// unauthenticated Noise-NN shape; `v2` is the committed, code-compared one.
pub const INFO: &[u8] = b"catcard-ncry-v2";

/// Prefix hashed in front of the host's public key to make its commitment.
pub const COMMIT_LABEL: &[u8] = b"catcard-pair-v2/commit";

/// HKDF `info` for the pairing code: the same secret and salt as the keys, a different
/// label, so the code says nothing about the keys beyond "these two match".
pub const CODE_INFO: &[u8] = b"catcard-pair-v2/code";

/// The code is shown as six decimal digits.
pub const CODE_MODULUS: u64 = 1_000_000;

/// How long a handshake may sit unpaired — the device user not yet answered, or the host's
/// `PairConfirm` not yet arrived — before the device tears it down. Two minutes: long
/// enough to read six digits twice, short enough that a prompt nobody is watching goes.
pub const PROMPT_MS: u32 = 120_000;

/// How long after a device key is handed out before another handshake may start.
///
/// Charged on every [`Responder`] the device creates, **not** only when a code is shown. A
/// relay that has shown the host one code wins only by re-rolling the device's code until
/// the two match -- and it can see each candidate code the moment it has the device's key,
/// before revealing anything, so a limit charged only on shown codes lets it discard
/// thousands of silent handshakes inside the host's wait. Charged per key, the host's two
/// minutes leave it about two dozen tries.
pub const ATTEMPT_COOLDOWN_MS: u32 = 5_000;

/// Handshakes dropped without a reveal -- replaced, abandoned, revealed wrongly, cut by a
/// bus reset -- before pairing is blocked until the person at the device acknowledges it.
///
/// An honest host reveals right after it commits; it drops a handshake only when it
/// crashes or is unplugged mid-way. A relay re-rolling the device's code drops one per
/// try. Three is room for a clumsy honest host and three chances in a million for a
/// relay, after which it needs the person to notice and let it go on.
pub const ABANDON_LIMIT: u8 = 3;

/// Why the device will not start a handshake right now.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Refusal {
    /// Inside [`ATTEMPT_COOLDOWN_MS`] of the last device key. Try again shortly.
    Cooling,
    /// [`ABANDON_LIMIT`] handshakes were dropped unrevealed; the device is showing a
    /// warning, and pairing waits until its user dismisses it.
    Locked,
}

/// The limits on pairing attempts, kept by the device across handshakes.
///
/// The commitment makes one handshake a one-in-a-million shot for a relay; this is what
/// keeps the relay from simply taking more shots. It holds no keys and reads no clock:
/// the caller reports time passing ([`tick`](Self::tick)) and each step of a handshake,
/// which is what lets the re-roll attack be tested on the host.
#[derive(Clone, Debug, Default)]
pub struct PairGuard {
    cooldown_ms: u32,
    /// A device key is out and its reveal has not arrived.
    pending: bool,
    abandoned: u8,
    locked: bool,
}

impl PairGuard {
    pub const fn new() -> Self {
        Self {
            cooldown_ms: 0,
            pending: false,
            abandoned: 0,
            locked: false,
        }
    }

    /// A `PairCommit` wants a device key. On `Ok` the caller creates the [`Responder`] --
    /// replacing any pending one, which this has already counted as abandoned -- and the
    /// cooldown starts.
    ///
    /// A refusal changes nothing: a pending handshake stays pending, uncounted.
    pub fn begin(&mut self) -> Result<(), Refusal> {
        if self.locked {
            return Err(Refusal::Locked);
        }
        if self.cooldown_ms > 0 {
            return Err(Refusal::Cooling);
        }
        if self.pending {
            // Replacing a key the host never revealed against: the re-roll.
            self.abandon();
            if self.locked {
                return Err(Refusal::Locked);
            }
        }
        self.cooldown_ms = ATTEMPT_COOLDOWN_MS;
        self.pending = true;
        Ok(())
    }

    /// The reveal matched the commitment: the code is on the screen, in front of a person.
    pub fn revealed(&mut self) {
        self.pending = false;
    }

    /// The pending handshake went away without a good reveal: a `PairAbort`, a reveal that
    /// missed its commitment, a bus reset. Counted like a replacement.
    pub fn dropped(&mut self) {
        if self.pending {
            self.abandon();
        }
    }

    /// Both sides accepted the code. What went before was an honest host's stumbles.
    pub fn paired(&mut self) {
        self.abandoned = 0;
    }

    /// Time passed, in milliseconds.
    pub fn tick(&mut self, ms: u32) {
        self.cooldown_ms = self.cooldown_ms.saturating_sub(ms);
    }

    /// Whether pairing is blocked, and how many handshakes were abandoned to get here.
    pub fn locked(&self) -> Option<u8> {
        self.locked.then_some(self.abandoned)
    }

    /// The person at the device saw the warning and let pairing go on. The count starts
    /// again, so a relay that is still there gets [`ABANDON_LIMIT`] more tries and then
    /// needs the person again.
    pub fn dismiss(&mut self) {
        self.locked = false;
        self.abandoned = 0;
    }

    fn abandon(&mut self) {
        self.pending = false;
        self.abandoned = self.abandoned.saturating_add(1);
        if self.abandoned >= ABANDON_LIMIT {
            self.locked = true;
        }
    }
}

/// Why a channel operation could not be completed.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// The peer's public key is a small-order point (its shared secret is the canonical
    /// zero). Rejected as RFC 7748 §6.1 permits and RFC 8446 §7.4.2 requires, rather than
    /// keying a channel off a value the peer could have forced.
    SmallOrderPeer,
    /// The revealed host key does not hash to the commitment the host sent first. Either a
    /// broken host or a relay trying to choose its key after seeing the device's.
    BadReveal,
    /// A record failed authentication: a wrong key, a corrupted or tampered record, or a
    /// replay or reorder (whose nonce is not the one expected next).
    BadTag,
    /// The direction's message counter is exhausted. Unreachable in practice — it is a
    /// 64-bit count — but a wrapped counter would reuse a nonce, so it is refused instead.
    Exhausted,
    /// No channel is open.
    Closed,
    /// A record shorter than a tag and an opcode, or longer than [`RECORD_MAX`].
    Size,
}

/// The host's commitment to its ephemeral public key:
/// `SHA-256(COMMIT_LABEL ‖ host_pub)`.
pub fn commitment(host_pub: &[u8; KEY_LEN]) -> [u8; COMMIT_LEN] {
    let mut sha = Sha256::new();
    sha.update(COMMIT_LABEL);
    sha.update(host_pub);
    let mut out = [0u8; COMMIT_LEN];
    out.copy_from_slice(sha.finalize().as_ref());
    out
}

/// Reduce eight uniformly random bytes to a six-digit code.
///
/// Big-endian `u64 mod 10^6`. The bias is at most 10^6 / 2^64 ≈ 5·10^-14 per value —
/// nothing a person comparing digits could ever exploit.
pub fn code_from(bytes: &[u8; 8]) -> u32 {
    (u64::from_be_bytes(*bytes) % CODE_MODULUS) as u32
}

/// A code as a person reads it: six digits, zero padded, grouped `123 456`.
pub fn code_text(code: u32) -> [u8; 7] {
    let mut c = code % CODE_MODULUS as u32;
    let mut out = *b"000 000";
    // Least significant first, skipping the space at index 3.
    for at in [6, 5, 4, 2, 1, 0] {
        out[at] = b'0' + (c % 10) as u8;
        c /= 10;
    }
    out
}

/// Constant-time equality of two commitments. They are not secret, but the comparison
/// costs nothing to make uniform and then nobody has to argue that it need not be.
fn same(a: &[u8; COMMIT_LEN], b: &[u8; COMMIT_LEN]) -> bool {
    let mut d = 0u8;
    for (x, y) in a.iter().zip(b) {
        d |= x ^ y;
    }
    d == 0
}

/// The nonce for message `counter` on one direction: the count little-endian in the low
/// eight bytes, the top four zero. Each direction has its own key, so both may start at
/// zero without ever sharing a (key, nonce) pair.
fn nonce(counter: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[..8].copy_from_slice(&counter.to_le_bytes());
    n
}

/// Derive the two directional keys and the pairing code from the shared secret, bound to
/// the whole transcript so the schedule commits to the exact handshake that produced it.
///
/// Returns `(initiator→responder, responder→initiator, code)`. The transcript is always
/// `commit ‖ responder_pub ‖ initiator_pub` — the order the bytes crossed the wire —
/// whichever side is deriving.
fn derive(
    dh: &[u8; KEY_LEN],
    commit: &[u8; COMMIT_LEN],
    responder_pub: &[u8; KEY_LEN],
    initiator_pub: &[u8; KEY_LEN],
) -> ([u8; 32], [u8; 32], u32) {
    let mut transcript = [0u8; COMMIT_LEN + 2 * KEY_LEN];
    transcript[..COMMIT_LEN].copy_from_slice(commit);
    transcript[COMMIT_LEN..COMMIT_LEN + KEY_LEN].copy_from_slice(responder_pub);
    transcript[COMMIT_LEN + KEY_LEN..].copy_from_slice(initiator_pub);

    let mut okm = [0u8; 64];
    hkdf::<Sha256>(&transcript, dh, INFO, &mut okm);
    let mut i2r = [0u8; 32];
    let mut r2i = [0u8; 32];
    i2r.copy_from_slice(&okm[..32]);
    r2i.copy_from_slice(&okm[32..]);
    okm.zeroize();

    let mut code = [0u8; 8];
    hkdf::<Sha256>(&transcript, dh, CODE_INFO, &mut code);
    let c = code_from(&code);
    code.zeroize();
    (i2r, r2i, c)
}

/// The device between `PairCommit` and `PairReveal`: its ephemeral scalar, the public key
/// it has already sent, and the commitment the host is bound to.
///
/// The scalar is wiped on drop. Not `Clone`, so one handshake's key is used once.
pub struct Responder {
    eph_priv: [u8; KEY_LEN],
    public: [u8; KEY_LEN],
    commit: [u8; COMMIT_LEN],
}

impl Drop for Responder {
    fn drop(&mut self) {
        self.eph_priv.zeroize();
    }
}

impl Responder {
    /// Take the host's commitment and a fresh ephemeral scalar from the HMAC-DRBG.
    pub fn new(eph_priv: &[u8; KEY_LEN], commit: &[u8; COMMIT_LEN]) -> Self {
        let public = X25519PrivateKey::from_bytes(*eph_priv).public_key();
        Responder {
            eph_priv: *eph_priv,
            public,
            commit: *commit,
        }
    }

    /// The device's ephemeral public key, the reply to `PairCommit`.
    pub fn public_key(&self) -> &[u8; KEY_LEN] {
        &self.public
    }

    /// The host's reveal: check it against the commitment and derive the session.
    ///
    /// The session is **not** paired; see [`Session::paired`].
    pub fn reveal(self, initiator_pub: &[u8; KEY_LEN]) -> Result<Session, Error> {
        if !same(&commitment(initiator_pub), &self.commit) {
            return Err(Error::BadReveal);
        }
        let sk = X25519PrivateKey::from_bytes(self.eph_priv);
        let mut dh = sk
            .diffie_hellman(initiator_pub)
            .map_err(|_| Error::SmallOrderPeer)?;
        let (i2r, r2i, code) = derive(&dh, &self.commit, &self.public, initiator_pub);
        dh.zeroize();
        // The device receives on initiator→responder and sends on responder→initiator.
        Ok(Session::new(r2i, i2r, code))
    }
}

/// The host between `PairCommit` and the device's reply. The firmware never builds one;
/// it is here so the two halves are tested against each other in one place.
pub struct Initiator {
    eph_priv: [u8; KEY_LEN],
    public: [u8; KEY_LEN],
    commit: [u8; COMMIT_LEN],
}

impl Drop for Initiator {
    fn drop(&mut self) {
        self.eph_priv.zeroize();
    }
}

impl Initiator {
    /// Start a handshake from a fresh ephemeral scalar.
    pub fn new(eph_priv: &[u8; KEY_LEN]) -> Self {
        let public = X25519PrivateKey::from_bytes(*eph_priv).public_key();
        Initiator {
            eph_priv: *eph_priv,
            public,
            commit: commitment(&public),
        }
    }

    /// The `PairCommit` payload.
    pub fn commitment(&self) -> &[u8; COMMIT_LEN] {
        &self.commit
    }

    /// The `PairReveal` payload.
    pub fn public_key(&self) -> &[u8; KEY_LEN] {
        &self.public
    }

    /// The device's public key arrived: derive the session and the code to show.
    pub fn finish(self, responder_pub: &[u8; KEY_LEN]) -> Result<Session, Error> {
        let sk = X25519PrivateKey::from_bytes(self.eph_priv);
        let mut dh = sk
            .diffie_hellman(responder_pub)
            .map_err(|_| Error::SmallOrderPeer)?;
        let (i2r, r2i, code) = derive(&dh, &self.commit, responder_pub, &self.public);
        dh.zeroize();
        // The host sends on initiator→responder and receives on responder→initiator.
        Ok(Session::new(i2r, r2i, code))
    }
}

/// What to do with a sealed request, by its inner opcode. See [`Session::admit`].
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Admit {
    /// A paired session's ordinary command: dispatch it.
    Dispatch,
    /// The host's `PairConfirm`. Answer with whether the session is now paired.
    Confirm,
    /// Anything but `PairConfirm` before the session is paired. Tear the session down.
    Refuse,
}

/// An established channel: one key and message counter per direction, the pairing code,
/// and the two halves of the pairing decision.
///
/// The keys are wiped on drop. There is no `Clone`: a copied counter would seal two
/// records under one nonce.
pub struct Session {
    send_key: [u8; 32],
    recv_key: [u8; 32],
    send_ctr: u64,
    recv_ctr: u64,
    code: u32,
    /// The device user pressed accept on the code.
    accepted: bool,
    /// The host's sealed `PairConfirm` authenticated.
    confirmed: bool,
    /// Milliseconds spent unpaired, against [`PROMPT_MS`].
    waited_ms: u32,
}

impl Drop for Session {
    fn drop(&mut self) {
        self.send_key.zeroize();
        self.recv_key.zeroize();
    }
}

impl Session {
    fn new(send_key: [u8; 32], recv_key: [u8; 32], code: u32) -> Self {
        Session {
            send_key,
            recv_key,
            send_ctr: 0,
            recv_ctr: 0,
            code,
            accepted: false,
            confirmed: false,
            waited_ms: 0,
        }
    }

    /// The six-digit pairing code for this handshake, `0..10^6`.
    pub fn code(&self) -> u32 {
        self.code
    }

    /// Whether the channel may carry commands: the device user accepted the code **and**
    /// the host's sealed `PairConfirm` authenticated. Only the device side ever becomes
    /// paired; a host session has nobody to accept on it.
    pub fn paired(&self) -> bool {
        self.accepted && self.confirmed
    }

    /// Whether the device user has yet to answer. A session still waiting is the one the
    /// pairing prompt is for.
    pub fn awaiting_user(&self) -> bool {
        !self.accepted
    }

    /// The device user accepted the code on the screen.
    pub fn accept(&mut self) {
        self.accepted = true;
    }

    /// Decide what a sealed request may do, by its inner opcode. Call after
    /// [`open`](Session::open) authenticated it.
    ///
    /// Before the session is paired the only record admitted is `PairConfirm`, which marks
    /// the host's half of the decision; anything else is refused, and the caller tears the
    /// session down — a host that sends commands before pairing is not following the
    /// protocol, and a channel nobody has agreed to must not carry them. After pairing a
    /// repeated `PairConfirm` is harmless and answered again.
    pub fn admit(&mut self, inner_op: u16) -> Admit {
        if inner_op == crate::Opcode::PairConfirm as u16 {
            self.confirmed = true;
            return Admit::Confirm;
        }
        if self.paired() {
            Admit::Dispatch
        } else {
            Admit::Refuse
        }
    }

    /// Count `gap_ms` against the pairing deadline. True once an unpaired session has
    /// waited [`PROMPT_MS`]: the caller tears it down. A paired session never expires.
    pub fn wait(&mut self, gap_ms: u32) -> bool {
        if self.paired() {
            return false;
        }
        self.waited_ms = self.waited_ms.saturating_add(gap_ms);
        self.waited_ms >= PROMPT_MS
    }

    /// Seal `buf` in place under the next send nonce and return the tag to append.
    ///
    /// The wire record is `buf` (now ciphertext) followed by the returned [`TAG_LEN`]
    /// bytes. Advances the send counter only on success.
    pub fn seal(&mut self, buf: &mut [u8]) -> Result<[u8; TAG_LEN], Error> {
        if self.send_ctr == u64::MAX {
            return Err(Error::Exhausted);
        }
        let aead = ChaCha20Poly1305::new(&self.send_key);
        let tag = aead.encrypt(&nonce(self.send_ctr), &[], buf);
        self.send_ctr += 1;
        Ok(tag)
    }

    /// Open a record in place: verify `tag` against the next receive nonce and, only if
    /// it matches, decrypt `buf`. On any failure `buf` is left as ciphertext and the
    /// receive counter does not advance, so a caller that drops the session on error
    /// never confuses a forged record for a gap.
    pub fn open(&mut self, buf: &mut [u8], tag: &[u8; TAG_LEN]) -> Result<(), Error> {
        if self.recv_ctr == u64::MAX {
            return Err(Error::Exhausted);
        }
        let aead = ChaCha20Poly1305::new(&self.recv_key);
        aead.decrypt(&nonce(self.recv_ctr), &[], buf, tag)
            .map_err(|_| Error::BadTag)?;
        self.recv_ctr += 1;
        Ok(())
    }
}

/// The device's end of the channel: at most one [`Session`], whatever the device keeps
/// for the life of that session (`S`), and a count of how many have been opened.
///
/// The count is what binds state to a session without keeping the session's keys around
/// to compare: a host request remembers the id it arrived under, and belongs to whoever
/// holds the channel only while [`id`](Self::id) still says that number and the channel
/// is open. A new handshake, a teardown and a bus reset all move past it for good.
///
/// `S` is reset to its default whenever a session is installed or closed, so anything the
/// device learned under one session -- which addresses a host was shown -- cannot outlive
/// it or leak into the next.
///
/// **Any failure closes it.** A record that does not authenticate, is the wrong size, or
/// cannot be sealed ends the session: a channel that has seen one forged record is not one
/// to keep trusting, and the host can renegotiate.
pub struct Channel<S: Default = ()> {
    session: Option<Session>,
    id: u32,
    state: S,
}

impl<S: Default> Default for Channel<S> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S: Default> Channel<S> {
    pub fn new() -> Self {
        Self {
            session: None,
            id: 0,
            state: S::default(),
        }
    }

    pub fn is_open(&self) -> bool {
        self.session.is_some()
    }

    /// Whether this channel may carry the host-wallet commands (addresses, signing).
    ///
    /// **The one place that decides it**: only a [paired](Session::paired) session -- the
    /// person compared the code on both screens and accepted on both sides. An open but
    /// unpaired session is still in its handshake and carries nothing but `PairConfirm`.
    pub fn host_wallet_allowed(&self) -> bool {
        self.session.as_ref().is_some_and(Session::paired)
    }

    /// The open session, if any: the pairing state lives on it.
    pub fn session(&self) -> Option<&Session> {
        self.session.as_ref()
    }

    /// [`session`](Self::session), to change -- a user's answer to the code, a tick of
    /// the pairing deadline.
    pub fn session_mut(&mut self) -> Option<&mut Session> {
        self.session.as_mut()
    }

    /// The number of the session opened most recently, open or not. Zero before any.
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Whether `id` names the session that is open now.
    pub fn is_current(&self, id: u32) -> bool {
        self.is_open() && id == self.id && id != 0
    }

    /// What the device keeps for the open session, or `None` when none is open.
    pub fn state(&self) -> Option<&S> {
        self.session.as_ref().map(|_| &self.state)
    }

    /// [`state`](Self::state), to change -- only for the session `id`, so a caller
    /// holding an old session's number cannot write into a new one.
    pub fn state_mut(&mut self, id: u32) -> Option<&mut S> {
        if self.is_current(id) {
            Some(&mut self.state)
        } else {
            None
        }
    }

    /// Replace whatever was open with `session`, under a new id and a fresh state.
    pub fn install(&mut self, session: Session) {
        self.id = self.id.wrapping_add(1).max(1);
        self.session = Some(session);
        self.state = S::default();
    }

    /// End the session, if one is open. Its keys are wiped as it drops, and its state is
    /// reset.
    pub fn close(&mut self) {
        self.session = None;
        self.state = S::default();
    }

    /// Open a sealed request record in place: `[ciphertext][tag]`. Returns the
    /// plaintext -- `[u16 opcode][payload]`, at least two bytes -- as a slice of `record`.
    ///
    /// Closes the channel on any failure, including a record of the wrong size.
    pub fn open_record<'b>(&mut self, record: &'b mut [u8]) -> Result<&'b mut [u8], Error> {
        let Some(session) = self.session.as_mut() else {
            return Err(Error::Closed);
        };
        if record.len() < OVERHEAD + 2 || record.len() > RECORD_MAX {
            self.close();
            return Err(Error::Size);
        }
        let ct_len = record.len() - TAG_LEN;
        let (ct, tag) = record.split_at_mut(ct_len);
        let mut t = [0u8; TAG_LEN];
        t.copy_from_slice(tag);
        match session.open(ct, &t) {
            Ok(()) => Ok(ct),
            Err(e) => {
                self.close();
                Err(e)
            }
        }
    }

    /// Seal `buf[..plain_len]` in place and write its tag after it; returns the record's
    /// length. `buf` must have [`TAG_LEN`] bytes of room past the plaintext. Closes the
    /// channel on failure.
    pub fn seal_record(&mut self, buf: &mut [u8], plain_len: usize) -> Result<usize, Error> {
        let Some(session) = self.session.as_mut() else {
            return Err(Error::Closed);
        };
        if plain_len + TAG_LEN > buf.len() {
            self.close();
            return Err(Error::Size);
        }
        match session.seal(&mut buf[..plain_len]) {
            Ok(tag) => {
                buf[plain_len..plain_len + TAG_LEN].copy_from_slice(&tag);
                Ok(plain_len + TAG_LEN)
            }
            Err(e) => {
                self.close();
                Err(e)
            }
        }
    }
}

#[cfg(test)]
mod tests {

    // ---------------------------------------------------------------------------------
    // PairGuard: the relay's re-roll, and an honest host's ordinary day.
    // ---------------------------------------------------------------------------------

    /// The attack this exists for: a relay takes a device key, sees from it that the code
    /// will not match the one the host is showing, and starts over without revealing. It
    /// cannot go faster than one key per cooldown, and three silent drops block pairing.
    #[test]
    fn a_relay_re_rolling_the_device_code_is_throttled_then_blocked() {
        let mut g = PairGuard::new();
        let mut keys = 0;
        let mut elapsed = 0u32;
        // The host waits two minutes; the relay commits every millisecond it can.
        while elapsed < PROMPT_MS {
            match g.begin() {
                Ok(()) => keys += 1,
                Err(Refusal::Cooling) => {}
                Err(Refusal::Locked) => break,
            }
            g.tick(1);
            elapsed += 1;
        }
        assert!(g.locked().is_some(), "silent re-rolls must end in a block");
        // The first key, then one per cooldown until the third drop locks it.
        assert_eq!(
            keys, ABANDON_LIMIT as u32,
            "keys handed out before the block"
        );
        assert_eq!(g.locked(), Some(ABANDON_LIMIT));
        // Blocked stays blocked, however long it waits.
        g.tick(u32::MAX);
        assert_eq!(g.begin(), Err(Refusal::Locked));
    }

    /// Without the per-key charge the same loop would have had thousands of keys; with it,
    /// a relay that also stays under the abandon limit (by revealing each time) gets one
    /// key per cooldown, and every one of those puts a code in front of the person.
    #[test]
    fn keys_are_charged_even_when_no_code_is_ever_shown() {
        let mut g = PairGuard::new();
        assert_eq!(g.begin(), Ok(()));
        assert_eq!(g.begin(), Err(Refusal::Cooling), "a second key at once");
        g.tick(ATTEMPT_COOLDOWN_MS - 1);
        assert_eq!(g.begin(), Err(Refusal::Cooling));
        g.tick(1);
        // The pending one is replaced now, and counted.
        assert_eq!(g.begin(), Ok(()));
        assert_eq!(g.locked(), None);
    }

    #[test]
    fn every_way_of_dropping_an_unrevealed_handshake_counts() {
        let mut g = PairGuard::new();
        for _ in 0..ABANDON_LIMIT {
            assert_eq!(g.begin(), Ok(()));
            g.dropped(); // abort, bad reveal, bus reset
            g.tick(ATTEMPT_COOLDOWN_MS);
        }
        assert_eq!(g.begin(), Err(Refusal::Locked));
    }

    /// An honest host commits, reveals, and the person decides. None of that is abandoning,
    /// whatever the answer, and pairing never blocks.
    #[test]
    fn an_honest_host_never_trips_the_block() {
        let mut g = PairGuard::new();
        for round in 0..20 {
            assert_eq!(g.begin(), Ok(()), "round {round}");
            g.revealed();
            g.dropped(); // the session ending after a reveal is not an abandon
            if round % 3 == 2 {
                g.paired();
            }
            g.tick(ATTEMPT_COOLDOWN_MS);
        }
        assert_eq!(g.locked(), None);
    }

    #[test]
    fn a_dismissed_block_gives_the_full_allowance_again() {
        let mut g = PairGuard::new();
        for _ in 0..ABANDON_LIMIT {
            let _ = g.begin();
            g.dropped();
            g.tick(ATTEMPT_COOLDOWN_MS);
        }
        assert!(g.locked().is_some());
        g.dismiss();
        assert_eq!(g.locked(), None);
        assert_eq!(g.begin(), Ok(()));
        // And a pairing that completes clears a partial count, so an honest host's slip
        // today does not count against it tomorrow.
        g.revealed();
        g.dropped();
        g.tick(ATTEMPT_COOLDOWN_MS);
        let _ = g.begin();
        g.dropped();
        g.paired();
        g.tick(ATTEMPT_COOLDOWN_MS);
        for _ in 0..ABANDON_LIMIT - 1 {
            let _ = g.begin();
            g.dropped();
            g.tick(ATTEMPT_COOLDOWN_MS);
        }
        assert_eq!(g.locked(), None, "the count restarted at the pairing");
    }

    use super::*;
    use crate::Opcode;

    // Two fixed ephemeral scalars, so the handshake is reproducible and a host
    // implementation (`tools/ncry.py --selftest`) can be checked against the same vector.
    const HOST_PRIV: [u8; 32] = [
        0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66,
        0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9,
        0x2c, 0x2a,
    ];
    const DEV_PRIV: [u8; 32] = [
        0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b, 0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80, 0x0e,
        0xe6, 0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd, 0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88,
        0xe0, 0xeb,
    ];
    // A third party's scalars, for the relay: one key facing each side.
    const RELAY_TO_DEV: [u8; 32] = [0x42; 32];
    const RELAY_TO_HOST: [u8; 32] = [0x24; 32];

    /// Run the handshake both sides, in wire order, and return (host, device) sessions.
    /// Neither is paired.
    fn handshake() -> (Session, Session) {
        let host = Initiator::new(&HOST_PRIV);
        let dev = Responder::new(&DEV_PRIV, host.commitment());
        let dev_pub = *dev.public_key();
        let host_pub = *host.public_key();
        let device = dev.reveal(&host_pub).unwrap();
        let host = host.finish(&dev_pub).unwrap();
        (host, device)
    }

    /// A handshake whose device session has been paired: accepted and confirmed.
    fn pair() -> (Session, Session) {
        let (host, mut device) = handshake();
        device.accept();
        assert_eq!(
            device.admit(Opcode::PairConfirm as u16),
            Admit::Confirm,
            "PairConfirm is always admitted"
        );
        assert!(device.paired());
        (host, device)
    }

    #[test]
    fn a_reveal_that_misses_the_commitment_is_refused() {
        let host = Initiator::new(&HOST_PRIV);
        let dev = Responder::new(&DEV_PRIV, host.commitment());
        // The relay's trick: commit to one key, reveal another chosen after seeing the
        // device's.
        let other = X25519PrivateKey::from_bytes(RELAY_TO_DEV).public_key();
        assert_eq!(dev.reveal(&other).err(), Some(Error::BadReveal));
    }

    #[test]
    fn a_single_flipped_bit_in_the_reveal_is_refused() {
        let host = Initiator::new(&HOST_PRIV);
        let dev = Responder::new(&DEV_PRIV, host.commitment());
        let mut reveal = *host.public_key();
        reveal[31] ^= 0x01;
        assert_eq!(dev.reveal(&reveal).err(), Some(Error::BadReveal));
    }

    #[test]
    fn the_commitment_is_the_labelled_hash_of_the_key() {
        let host = Initiator::new(&HOST_PRIV);
        let mut sha = Sha256::new();
        sha.update(b"catcard-pair-v2/commit");
        sha.update(host.public_key());
        assert_eq!(host.commitment()[..], sha.finalize().as_ref()[..]);
    }

    #[test]
    fn both_sides_derive_the_same_code() {
        let (host, device) = handshake();
        assert_eq!(host.code(), device.code());
        assert!(host.code() < CODE_MODULUS as u32);
        assert_eq!(device.code(), KAT_CODE);
    }

    #[test]
    fn a_relay_yields_different_codes_on_the_two_screens() {
        // host <-> relay: the host commits to its key, the relay answers with its own.
        let host = Initiator::new(&HOST_PRIV);
        let relay_as_dev = Responder::new(&RELAY_TO_HOST, host.commitment());
        let host_pub = *host.public_key();
        let relay_host_side = relay_as_dev.public_key().to_owned();
        let host_session = host.finish(&relay_host_side).unwrap();
        let relay_dev_facing = relay_as_dev.reveal(&host_pub).unwrap();
        // The relay's two host-side codes agree -- it ran a real handshake with the host.
        assert_eq!(host_session.code(), relay_dev_facing.code());

        // relay <-> device: the relay is the host now, with its own commitment.
        let relay_as_host = Initiator::new(&RELAY_TO_DEV);
        let dev = Responder::new(&DEV_PRIV, relay_as_host.commitment());
        let dev_pub = *dev.public_key();
        let relay_pub = *relay_as_host.public_key();
        let device_session = dev.reveal(&relay_pub).unwrap();
        let relay_host_facing = relay_as_host.finish(&dev_pub).unwrap();
        assert_eq!(device_session.code(), relay_host_facing.code());

        // What the two people compare: the host's screen against the device's.
        assert_ne!(host_session.code(), device_session.code());
    }

    #[test]
    fn codes_are_six_digits_and_spread_evenly() {
        // Feed the reduction a deterministic stream of SHA-256 output and bucket by the
        // leading digit: a biased reduction (taking one byte, say, or mod 10^6 of a u32
        // with a skew) would crowd some buckets. 100k samples, each bucket expecting 10k.
        let mut buckets = [0u32; 10];
        let mut seed = [0u8; 32];
        for i in 0u32..100_000 {
            if i % 4 == 0 {
                let mut sha = Sha256::new();
                sha.update(&seed);
                sha.update(&i.to_le_bytes());
                seed.copy_from_slice(sha.finalize().as_ref());
            }
            let at = (i % 4) as usize * 8;
            let c = code_from(seed[at..at + 8].try_into().unwrap());
            assert!(c < 1_000_000);
            buckets[(c / 100_000) as usize] += 1;
        }
        for (d, n) in buckets.iter().enumerate() {
            assert!(
                (9_500..=10_500).contains(n),
                "leading digit {d} seen {n} times of 100k"
            );
        }
    }

    #[test]
    fn a_code_reads_as_two_groups_of_three() {
        assert_eq!(&code_text(123_456), b"123 456");
        assert_eq!(&code_text(7), b"000 007");
        assert_eq!(&code_text(0), b"000 000");
        assert_eq!(&code_text(999_999), b"999 999");
        assert_eq!(&code_text(40_500), b"040 500");
    }

    #[test]
    fn sealed_records_before_pair_confirm_are_refused() {
        let (_host, mut device) = handshake();
        assert!(!device.paired());
        for op in [
            Opcode::Ping,
            Opcode::Identify,
            Opcode::ReadLog,
            Opcode::NcryMsg,
        ] {
            assert_eq!(device.admit(op as u16), Admit::Refuse, "{op:?}");
        }
        // An unknown inner opcode is no different.
        assert_eq!(device.admit(0x7777), Admit::Refuse);
    }

    #[test]
    fn pairing_needs_both_the_user_and_the_host() {
        // Host confirms first; nothing is paired until the user accepts.
        let (_h, mut device) = handshake();
        assert_eq!(device.admit(Opcode::PairConfirm as u16), Admit::Confirm);
        assert!(!device.paired());
        assert_eq!(device.admit(Opcode::Ping as u16), Admit::Refuse);
        device.accept();
        assert!(device.paired());
        assert_eq!(device.admit(Opcode::Ping as u16), Admit::Dispatch);

        // User accepts first; nothing is paired until the host confirms.
        let (_h, mut device) = handshake();
        device.accept();
        assert!(!device.paired());
        assert_eq!(device.admit(Opcode::Identify as u16), Admit::Refuse);
        let (_h, mut device) = handshake();
        device.accept();
        assert_eq!(device.admit(Opcode::PairConfirm as u16), Admit::Confirm);
        assert!(device.paired());
    }

    #[test]
    fn an_unpaired_session_expires_and_a_paired_one_does_not() {
        let (_h, mut device) = handshake();
        assert!(!device.wait(PROMPT_MS - 1));
        assert!(device.wait(1));

        let (_h, mut device) = pair();
        assert!(!device.wait(u32::MAX));
        assert!(!device.wait(u32::MAX));
    }

    #[test]
    fn directions_agree_and_round_trip() {
        let (mut host, mut device) = pair();

        // host → device
        let mut buf = *b"xpub-secret-payload";
        let plain = buf;
        let tag = host.seal(&mut buf).unwrap();
        assert_ne!(buf, plain, "ciphertext must differ from plaintext");
        device.open(&mut buf, &tag).unwrap();
        assert_eq!(buf, plain);

        // device → host
        let mut reply = *b"here-is-your-address";
        let reply_plain = reply;
        let tag = device.seal(&mut reply).unwrap();
        host.open(&mut reply, &tag).unwrap();
        assert_eq!(reply, reply_plain);
    }

    #[test]
    fn a_relayed_record_does_not_open() {
        // The relay forwards the host's sealed record to the device unchanged: the keys
        // differ, so it is refused -- a relay has to re-seal, which means reading it,
        // which is what the code comparison is there to notice.
        let host = Initiator::new(&HOST_PRIV);
        let relay_as_dev = Responder::new(&RELAY_TO_HOST, host.commitment());
        let relay_pub = *relay_as_dev.public_key();
        let mut host_session = host.finish(&relay_pub).unwrap();
        let relay_as_host = Initiator::new(&RELAY_TO_DEV);
        let dev = Responder::new(&DEV_PRIV, relay_as_host.commitment());
        let rpub = *relay_as_host.public_key();
        let mut device_session = dev.reveal(&rpub).unwrap();
        let mut rec = *b"confirm";
        let tag = host_session.seal(&mut rec).unwrap();
        assert_eq!(device_session.open(&mut rec, &tag), Err(Error::BadTag));
    }

    #[test]
    fn the_two_directions_use_different_keys() {
        let (host, _device) = handshake();
        assert_ne!(host.send_key, host.recv_key);
    }

    #[test]
    fn a_flipped_ciphertext_byte_is_rejected() {
        let (mut host, mut device) = pair();
        let mut buf = *b"sensitive";
        let tag = host.seal(&mut buf).unwrap();
        buf[0] ^= 1;
        assert_eq!(device.open(&mut buf, &tag), Err(Error::BadTag));
    }

    #[test]
    fn a_flipped_tag_bit_is_rejected() {
        let (mut host, mut device) = pair();
        let mut buf = *b"sensitive";
        let mut tag = host.seal(&mut buf).unwrap();
        tag[0] ^= 1;
        assert_eq!(device.open(&mut buf, &tag), Err(Error::BadTag));
    }

    #[test]
    fn a_replayed_record_is_rejected() {
        let (mut host, mut device) = pair();

        let mut first = *b"record-zero";
        let saved = first;
        let first_tag = host.seal(&mut first).unwrap();
        device.open(&mut first, &first_tag).unwrap();

        // A second, distinct record advances the device's expected counter.
        let mut second = *b"record-one!";
        let second_tag = host.seal(&mut second).unwrap();
        device.open(&mut second, &second_tag).unwrap();

        // Replaying record zero now authenticates against counter 2's nonce: rejected.
        let mut replay = saved;
        assert_eq!(device.open(&mut replay, &first_tag), Err(Error::BadTag));
    }

    #[test]
    fn a_reordered_record_is_rejected() {
        let (mut host, mut device) = pair();
        let mut a = *b"first-first";
        let ta = host.seal(&mut a).unwrap();
        let mut b = *b"then-secnd!";
        let tb = host.seal(&mut b).unwrap();
        // Deliver the second record first: its nonce (1) is not the one expected (0).
        assert_eq!(device.open(&mut b, &tb), Err(Error::BadTag));
        // The in-order first record still opens.
        device.open(&mut a, &ta).unwrap();
    }

    #[test]
    fn a_small_order_peer_key_is_rejected() {
        // The all-zero u-coordinate is small-order; its shared secret is canonical zero.
        let zero = [0u8; 32];
        let dev = Responder::new(&DEV_PRIV, &commitment(&zero));
        assert_eq!(dev.reveal(&zero).err(), Some(Error::SmallOrderPeer));
        assert_eq!(
            Initiator::new(&HOST_PRIV).finish(&zero).err(),
            Some(Error::SmallOrderPeer)
        );
    }

    #[test]
    fn an_empty_payload_still_authenticates() {
        let (mut host, mut device) = pair();
        let mut empty: [u8; 0] = [];
        let tag = host.seal(&mut empty).unwrap();
        device.open(&mut empty, &tag).unwrap();
        // A wrong tag on an empty record is still caught.
        let mut bad = tag;
        bad[0] ^= 1;
        assert_eq!(device.open(&mut [], &bad), Err(Error::BadTag));
    }

    // A cross-implementation known-answer test. `tools/ncry.py --selftest` derives the
    // same commitment, code and key schedule from the same two scalars; sealing the
    // counter-0 record `b"catcard"` host→device with an empty AAD must produce exactly
    // these bytes on both sides. If this vector ever changes, the host and firmware have
    // diverged.
    #[test]
    fn known_answer_pins_the_wire_format() {
        let host = Initiator::new(&HOST_PRIV);
        assert_eq!(*host.commitment(), KAT_COMMIT);
        let (mut host, _device) = handshake();
        assert_eq!(host.code(), KAT_CODE);
        let mut buf = *b"catcard";
        let tag = host.seal(&mut buf).unwrap();
        let mut record = [0u8; 7 + TAG_LEN];
        record[..7].copy_from_slice(&buf);
        record[7..].copy_from_slice(&tag);
        assert_eq!(record, KAT_RECORD);
    }

    // SHA-256("catcard-pair-v2/commit" ‖ X25519(HOST_PRIV, 9)).
    const KAT_COMMIT: [u8; 32] = [
        65, 181, 194, 108, 161, 34, 111, 179, 156, 98, 166, 84, 21, 115, 147, 169, 108, 1, 121,
        169, 26, 246, 122, 111, 98, 247, 189, 154, 215, 47, 20, 74,
    ];
    // The code both screens show for the fixed scalars.
    const KAT_CODE: u32 = 398_660;
    // Counter-0 seal of b"catcard" host→device: seven ciphertext bytes, sixteen tag bytes.
    const KAT_RECORD: [u8; 7 + TAG_LEN] = [
        128, 168, 83, 37, 40, 20, 198, 221, 119, 225, 110, 89, 217, 140, 246, 68, 129, 191, 40,
        248, 83, 179, 22,
    ];

    /// Frame a request the way a host does: a START frame, then CONT frames.
    fn frames(opcode: u16, payload: &[u8]) -> Vec<[u8; crate::REPORT_LEN]> {
        use crate::{CONT_PAYLOAD, KIND_CONT, KIND_START, REPORT_LEN, START_PAYLOAD};
        let mut out = Vec::new();
        let mut f = [0u8; REPORT_LEN];
        f[0] = KIND_START;
        f[2..4].copy_from_slice(&opcode.to_le_bytes());
        f[4..8].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        let n = payload.len().min(START_PAYLOAD);
        f[8..8 + n].copy_from_slice(&payload[..n]);
        out.push(f);
        let mut seq = 1u8;
        for chunk in payload[n..].chunks(CONT_PAYLOAD) {
            let mut f = [0u8; REPORT_LEN];
            f[0] = KIND_CONT;
            f[1] = seq;
            f[2..2 + chunk.len()].copy_from_slice(chunk);
            out.push(f);
            seq = seq.wrapping_add(1);
        }
        out
    }

    /// A sealed request of `plain_len` bytes, as the host would send it.
    fn sealed_request(host: &mut Session, plain_len: usize) -> (Vec<u8>, Vec<u8>) {
        let mut plain: Vec<u8> = (0..plain_len).map(|i| (i * 7 + 3) as u8).collect();
        plain[..2].copy_from_slice(&0x0052u16.to_le_bytes());
        let original = plain.clone();
        let tag = host.seal(&mut plain).unwrap();
        plain.extend_from_slice(&tag);
        (plain, original)
    }

    /// Feed frames through the reassembler into one buffer, as the device gathers a
    /// multi-frame record.
    fn gather(frames: &[[u8; crate::REPORT_LEN]]) -> Vec<u8> {
        let mut r = crate::Reassembler::new();
        let mut got = Vec::new();
        for f in frames {
            let p = r.feed(f).unwrap();
            got.extend_from_slice(p.payload);
        }
        assert!(!r.in_progress());
        got
    }

    fn channel_pair() -> (Session, Channel<u32>) {
        let (host, device) = pair();
        let mut ch = Channel::new();
        ch.install(device);
        (host, ch)
    }

    #[test]
    fn a_multi_frame_record_round_trips() {
        let (mut host, mut ch) = channel_pair();
        // A full-size request: sixteen-odd frames.
        let (record, original) = sealed_request(&mut host, PLAIN_MAX);
        assert_eq!(record.len(), RECORD_MAX);
        let fs = frames(0x0041, &record);
        assert!(fs.len() > 1, "must span frames");
        let mut got = gather(&fs);
        let plain = ch.open_record(&mut got).unwrap();
        assert_eq!(plain, &original[..]);
        assert!(ch.is_open());

        // The next record, a short one, still opens: the counters moved in step.
        let (mut record, original) = sealed_request(&mut host, 40);
        let plain = ch.open_record(&mut record).unwrap();
        assert_eq!(plain, &original[..]);
    }

    #[test]
    fn a_tampered_multi_frame_record_tears_the_session_down() {
        let (mut host, mut ch) = channel_pair();
        let id = ch.id();
        let (record, _) = sealed_request(&mut host, 700);
        let mut fs = frames(0x0041, &record);
        // One bit, in a continuation frame well past the first.
        fs[5][10] ^= 0x01;
        let mut got = gather(&fs);
        assert_eq!(ch.open_record(&mut got), Err(Error::BadTag));
        assert!(!ch.is_open(), "a forged record ends the session");
        assert!(!ch.is_current(id));
        // And nothing opens on it afterwards.
        let (mut next, _) = sealed_request(&mut host, 40);
        assert_eq!(ch.open_record(&mut next), Err(Error::Closed));
    }

    #[test]
    fn an_oversized_record_is_refused_and_closes() {
        let (mut host, mut ch) = channel_pair();
        let (mut record, _) = sealed_request(&mut host, PLAIN_MAX + 1);
        assert_eq!(ch.open_record(&mut record), Err(Error::Size));
        assert!(!ch.is_open());
    }

    #[test]
    fn a_new_handshake_moves_the_id_on() {
        let (_, mut ch) = channel_pair();
        let first = ch.id();
        assert!(ch.is_current(first));
        let (_, device) = pair();
        ch.install(device);
        assert!(!ch.is_current(first));
        assert!(ch.is_current(ch.id()));
        ch.close();
        assert!(!ch.is_current(ch.id()));
    }

    /// The host-wallet commands need a paired session, not merely an open one: after the
    /// handshake the channel is open and still refuses them, and only both halves of the
    /// acceptance -- the person at the device, and the host's sealed `PairConfirm` --
    /// let them through.
    #[test]
    fn host_wallet_needs_a_paired_session_not_just_an_open_one() {
        let (_, device) = handshake();
        let mut ch: Channel<u32> = Channel::new();
        ch.install(device);
        assert!(ch.is_open());
        assert!(!ch.host_wallet_allowed(), "open but unpaired");

        // The device user accepts; the host has not confirmed yet.
        ch.session_mut().unwrap().accept();
        assert!(!ch.host_wallet_allowed(), "one half of the acceptance");

        // The sealed PairConfirm completes it.
        assert_eq!(
            ch.session_mut().unwrap().admit(Opcode::PairConfirm as u16),
            Admit::Confirm
        );
        assert!(ch.host_wallet_allowed(), "paired");

        ch.close();
        assert!(!ch.host_wallet_allowed());
    }

    #[test]
    fn session_state_is_dropped_with_the_session() {
        let (_, mut ch) = channel_pair();
        let id = ch.id();
        *ch.state_mut(id).unwrap() = 42;
        assert_eq!(ch.state(), Some(&42));
        // An old session's number cannot reach the new one's state.
        let (_, device) = pair();
        ch.install(device);
        assert_eq!(ch.state(), Some(&0), "a new session starts clean");
        assert!(ch.state_mut(id).is_none());
        *ch.state_mut(ch.id()).unwrap() = 7;
        ch.close();
        assert_eq!(ch.state(), None);
        assert!(!ch.host_wallet_allowed());
    }

    #[test]
    fn a_reply_seals_and_the_host_opens_it() {
        let (mut host, mut ch) = channel_pair();
        let mut buf = [0u8; 64];
        buf[..5].copy_from_slice(b"hello");
        let n = ch.seal_record(&mut buf, 5).unwrap();
        assert_eq!(n, 5 + TAG_LEN);
        let mut tag = [0u8; TAG_LEN];
        tag.copy_from_slice(&buf[5..n]);
        host.open(&mut buf[..5], &tag).unwrap();
        assert_eq!(&buf[..5], b"hello");
    }
}
