//! IKE message fragmentation (RFC 7383), cipher-agile.
//!
//! A too-large encrypted message is sent as several IKE messages, each carrying
//! one **SKF** (Encrypted and Authenticated Fragment) payload instead of `SK`.
//! Each fragment is independently sealed under the negotiated [`SkCipher`] --
//! AEAD (AES-GCM/ChaCha20-Poly1305) or classic (AES-CBC/3DES-CBC + a separate
//! integrity key), the same two framings [`crate::ikev2::sk`] uses for the
//! plain `SK{}` payload, with the fragment header (Fragment Number + Total
//! Fragments) folded into what each framing authenticates.
//!
//! - **AEAD**: SKF body on the wire = IV(8) ‖ ciphertext ‖ ICV/tag. AAD = IKE
//!   header ‖ SKF generic header ‖ FragNum ‖ Total (everything before the IV).
//! - **Classic**: SKF body on the wire = IV(block size) ‖ CBC-ciphertext
//!   (block-aligned) ‖ ICV, where the ICV is `IntegAlgorithm::compute` over
//!   IKE header ‖ SKF generic header ‖ FragNum ‖ Total ‖ IV ‖ ciphertext --
//!   the same "MAC covers everything up to itself" shape `SK{}`'s CBC framing
//!   uses, just with FragNum/Total additionally covered.

use std::collections::BTreeMap;

use crate::error::IkeError;
use crate::ikev2::message::{ExchangeType, IkeHeader, PayloadType};
use crate::ikev2::sk::{
    aead_nonce, aead_open_dispatch, aead_seal_dispatch, cbc_decrypt, cbc_encrypt, ct_eq, expand_iv, SkCipher,
};

const IV_LEN: usize = 8; // AEAD explicit IV
const SKF_EXTRA: usize = 4; // Fragment Number (2) + Total Fragments (2)

/// Split a full inner-payload byte string into `total` SKF-payload IKE messages,
/// sealed under `cipher`. `header` supplies the SPIs / exchange type / message
/// id (its `next_payload` and `length` are set per fragment). `first_inner` is
/// the type of the first inner payload (recorded only in fragment #1). `sk_e`
/// (and, for a classic cipher, `sk_a`) are the key material for our direction,
/// sized per [`SkCipher::key_len`]/[`SkCipher::salt_len`] (AEAD) or the
/// negotiated `IntegAlgorithm::key_len` (classic). `iv_base` seeds a unique
/// per-fragment IV (the caller ensures global uniqueness under the key).
/// `content_per_fragment` is the max plaintext bytes per fragment.
#[allow(clippy::too_many_arguments)]
pub fn build_fragments(
    cipher: SkCipher,
    header: &IkeHeader,
    first_inner: PayloadType,
    inner: &[u8],
    sk_e: &[u8],
    sk_a: &[u8],
    iv_base: u64,
    content_per_fragment: usize,
) -> Result<Vec<Vec<u8>>, IkeError> {
    if content_per_fragment == 0 {
        return Err(IkeError::Crypto("fragment content size must be > 0"));
    }
    let chunks: Vec<&[u8]> = if inner.is_empty() {
        vec![&[][..]]
    } else {
        inner.chunks(content_per_fragment).collect()
    };
    let total = chunks.len() as u16;

    let mut out = Vec::with_capacity(chunks.len());
    for (i, chunk) in chunks.iter().enumerate() {
        let frag_num = (i + 1) as u16;
        let iv_seed = iv_base.wrapping_add(frag_num as u64).to_be_bytes();

        let msg = if cipher.is_aead() {
            seal_fragment_aead(cipher, header, first_inner, frag_num, total, chunk, sk_e, &iv_seed)?
        } else {
            seal_fragment_cbc(cipher, header, first_inner, frag_num, total, chunk, sk_e, sk_a, &iv_seed)?
        };
        out.push(msg);
    }
    Ok(out)
}

fn skf_gen_header(frag_num: u16, first_inner: PayloadType, skf_payload_len: u16) -> [u8; 4] {
    let mut skf_gen = [0u8; 4];
    skf_gen[0] = if frag_num == 1 { first_inner.to_u8() } else { 0 };
    skf_gen[1] = 0; // critical + reserved
    skf_gen[2..4].copy_from_slice(&skf_payload_len.to_be_bytes());
    skf_gen
}

#[allow(clippy::too_many_arguments)]
fn seal_fragment_aead(
    cipher: SkCipher,
    header: &IkeHeader,
    first_inner: PayloadType,
    frag_num: u16,
    total: u16,
    chunk: &[u8],
    sk_e: &[u8],
    iv_seed: &[u8; 8],
) -> Result<Vec<u8>, IkeError> {
    let key_len = cipher.key_len();
    if sk_e.len() != key_len + cipher.salt_len() {
        return Err(IkeError::Crypto("SK_e has the wrong length for the negotiated AEAD cipher"));
    }
    let (key, salt) = sk_e.split_at(key_len);

    // plaintext = chunk ‖ pad_length(0) -- AEAD needs no block padding, only
    // the one-byte Pad Length field RFC 7296 §3.14 still requires.
    let mut plaintext = chunk.to_vec();
    plaintext.push(0);

    let skf_payload_len = (4 + SKF_EXTRA + IV_LEN + plaintext.len() + cipher.icv_len()) as u16;
    let total_len = IkeHeader::LEN + skf_payload_len as usize;

    let mut hdr = *header;
    hdr.next_payload = PayloadType::EncryptedFragment;
    hdr.length = total_len as u32;
    let hdr_bytes = hdr.to_bytes();
    let skf_gen = skf_gen_header(frag_num, first_inner, skf_payload_len);

    // AAD = IKE header ‖ SKF generic header ‖ FragNum ‖ Total (before the IV).
    let mut aad = Vec::with_capacity(hdr_bytes.len() + 4 + SKF_EXTRA);
    aad.extend_from_slice(&hdr_bytes);
    aad.extend_from_slice(&skf_gen);
    aad.extend_from_slice(&frag_num.to_be_bytes());
    aad.extend_from_slice(&total.to_be_bytes());

    let nonce = aead_nonce(salt, iv_seed);
    let ct_and_tag = aead_seal_dispatch(cipher, key, &nonce, &aad, &plaintext)?;

    let mut msg = Vec::with_capacity(total_len);
    msg.extend_from_slice(&hdr_bytes);
    msg.extend_from_slice(&skf_gen);
    msg.extend_from_slice(&frag_num.to_be_bytes());
    msg.extend_from_slice(&total.to_be_bytes());
    msg.extend_from_slice(iv_seed);
    msg.extend_from_slice(&ct_and_tag);
    Ok(msg)
}

#[allow(clippy::too_many_arguments)]
fn seal_fragment_cbc(
    cipher: SkCipher,
    header: &IkeHeader,
    first_inner: PayloadType,
    frag_num: u16,
    total: u16,
    chunk: &[u8],
    sk_e: &[u8],
    sk_a: &[u8],
    iv_seed: &[u8; 8],
) -> Result<Vec<u8>, IkeError> {
    let block = cipher.block_len();
    let icv_len = cipher.icv_len();
    let integ = cipher.integ_algorithm().expect("seal_fragment_cbc called with a non-CBC cipher");

    // plaintext = chunk ‖ zero padding ‖ pad_length byte, block-aligned.
    let unpadded = chunk.len() + 1;
    let pad = (block - (unpadded % block)) % block;
    let mut plaintext = Vec::with_capacity(chunk.len() + pad + 1);
    plaintext.extend_from_slice(chunk);
    plaintext.resize(plaintext.len() + pad, 0);
    plaintext.push(pad as u8);

    let iv = expand_iv(iv_seed, block);

    let skf_payload_len = (4 + SKF_EXTRA + block + plaintext.len() + icv_len) as u16;
    let total_len = IkeHeader::LEN + skf_payload_len as usize;

    let mut hdr = *header;
    hdr.next_payload = PayloadType::EncryptedFragment;
    hdr.length = total_len as u32;
    let hdr_bytes = hdr.to_bytes();
    let skf_gen = skf_gen_header(frag_num, first_inner, skf_payload_len);

    let ciphertext = cbc_encrypt(cipher, sk_e, &iv, &plaintext)?;

    // ICV = truncated HMAC over IKE header ‖ SKF generic header ‖ FragNum ‖
    // Total ‖ IV ‖ ciphertext -- everything up to the ICV itself.
    let mut mac_input = Vec::with_capacity(hdr_bytes.len() + 4 + SKF_EXTRA + iv.len() + ciphertext.len());
    mac_input.extend_from_slice(&hdr_bytes);
    mac_input.extend_from_slice(&skf_gen);
    mac_input.extend_from_slice(&frag_num.to_be_bytes());
    mac_input.extend_from_slice(&total.to_be_bytes());
    mac_input.extend_from_slice(&iv);
    mac_input.extend_from_slice(&ciphertext);
    let icv = integ.compute(sk_a, &mac_input);

    let mut msg = Vec::with_capacity(total_len);
    msg.extend_from_slice(&hdr_bytes);
    msg.extend_from_slice(&skf_gen);
    msg.extend_from_slice(&frag_num.to_be_bytes());
    msg.extend_from_slice(&total.to_be_bytes());
    msg.extend_from_slice(&iv);
    msg.extend_from_slice(&ciphertext);
    msg.extend_from_slice(&icv);
    Ok(msg)
}

struct Fragment {
    frag_num: u16,
    total: u16,
    next_payload: u8,
    content: Vec<u8>,
}

fn open_fragment(cipher: SkCipher, message: &[u8], sk_e: &[u8], sk_a: &[u8]) -> Result<Fragment, IkeError> {
    if cipher.is_aead() {
        open_fragment_aead(cipher, message, sk_e)
    } else {
        open_fragment_cbc(cipher, message, sk_e, sk_a)
    }
}

fn open_fragment_aead(cipher: SkCipher, message: &[u8], sk_e: &[u8]) -> Result<Fragment, IkeError> {
    let key_len = cipher.key_len();
    if sk_e.len() != key_len + cipher.salt_len() {
        return Err(IkeError::Crypto("SK_e has the wrong length for the negotiated AEAD cipher"));
    }
    let (key, salt) = sk_e.split_at(key_len);

    let header = IkeHeader::parse(message)?;
    if header.next_payload != PayloadType::EncryptedFragment {
        return Err(IkeError::MissingPayload("SKF"));
    }
    let body = &message[IkeHeader::LEN..];
    let min_body = 4 + SKF_EXTRA + IV_LEN + cipher.icv_len();
    if body.len() < min_body {
        return Err(IkeError::Truncated { need: min_body, have: body.len() });
    }
    let next_payload = body[0];
    let skf_payload_len = u16::from_be_bytes([body[2], body[3]]) as usize;
    if skf_payload_len < min_body || skf_payload_len > body.len() {
        return Err(IkeError::BadLength { declared: skf_payload_len, available: body.len() });
    }
    let frag_num = u16::from_be_bytes([body[4], body[5]]);
    let total = u16::from_be_bytes([body[6], body[7]]);
    let iv: [u8; IV_LEN] = body[8..16].try_into().unwrap();
    let ct_and_tag = &body[16..skf_payload_len];

    let aad = &message[..IkeHeader::LEN + 4 + SKF_EXTRA];
    let nonce = aead_nonce(salt, &iv);
    let plaintext = aead_open_dispatch(cipher, key, &nonce, aad, ct_and_tag)?;

    let pad_len = *plaintext.last().ok_or(IkeError::Crypto("empty fragment"))? as usize;
    if pad_len + 1 > plaintext.len() {
        return Err(IkeError::Crypto("pad length exceeds fragment"));
    }
    Ok(Fragment {
        frag_num,
        total,
        next_payload,
        content: plaintext[..plaintext.len() - 1 - pad_len].to_vec(),
    })
}

fn open_fragment_cbc(cipher: SkCipher, message: &[u8], sk_e: &[u8], sk_a: &[u8]) -> Result<Fragment, IkeError> {
    let block = cipher.block_len();
    let icv_len = cipher.icv_len();
    let integ = cipher.integ_algorithm().expect("open_fragment_cbc called with a non-CBC cipher");

    let header = IkeHeader::parse(message)?;
    if header.next_payload != PayloadType::EncryptedFragment {
        return Err(IkeError::MissingPayload("SKF"));
    }
    let body = &message[IkeHeader::LEN..];
    let min_body = 4 + SKF_EXTRA + block + icv_len;
    if body.len() < min_body {
        return Err(IkeError::Truncated { need: min_body, have: body.len() });
    }
    let next_payload = body[0];
    let skf_payload_len = u16::from_be_bytes([body[2], body[3]]) as usize;
    if skf_payload_len < min_body || skf_payload_len > body.len() {
        return Err(IkeError::BadLength { declared: skf_payload_len, available: body.len() });
    }
    let frag_num = u16::from_be_bytes([body[4], body[5]]);
    let total = u16::from_be_bytes([body[6], body[7]]);

    let skf_body = &body[8..skf_payload_len];
    let iv = &skf_body[..block];
    let ct = &skf_body[block..skf_body.len() - icv_len];
    let icv = &skf_body[skf_body.len() - icv_len..];
    if ct.is_empty() || ct.len() % block != 0 {
        return Err(IkeError::Crypto("CBC ciphertext not block-aligned"));
    }

    let mut mac_input = Vec::with_capacity(IkeHeader::LEN + 4 + SKF_EXTRA + iv.len() + ct.len());
    mac_input.extend_from_slice(&message[..IkeHeader::LEN + 4 + SKF_EXTRA]);
    mac_input.extend_from_slice(iv);
    mac_input.extend_from_slice(ct);
    let expected_icv = integ.compute(sk_a, &mac_input);
    if !ct_eq(&expected_icv, icv) {
        return Err(IkeError::BadIntegrity);
    }

    let plaintext = cbc_decrypt(cipher, sk_e, iv, ct)?;
    let pad_len = *plaintext.last().ok_or(IkeError::Crypto("empty fragment"))? as usize;
    if pad_len + 1 > plaintext.len() {
        return Err(IkeError::Crypto("pad length exceeds fragment"));
    }
    Ok(Fragment {
        frag_num,
        total,
        next_payload,
        content: plaintext[..plaintext.len() - 1 - pad_len].to_vec(),
    })
}

/// Read a fragment's Fragment Number / Total Fragments straight off the
/// wire, without verifying its AEAD tag / CBC ICV. Both fields sit in the
/// SKF generic header, which is authenticated but not encrypted under either
/// framing (see the module docs), so this is cheap enough for a caller to
/// use as a queueing/deduplication key *before* paying for a full decrypt on
/// every arrival. Never trust the returned numbers for anything beyond that
/// bookkeeping -- [`reassemble`] still independently authenticates every
/// fragment's content once a full set is in hand.
pub fn peek_fragment_header(message: &[u8]) -> Result<(u16, u16), IkeError> {
    let header = IkeHeader::parse(message)?;
    if header.next_payload != PayloadType::EncryptedFragment {
        return Err(IkeError::MissingPayload("SKF"));
    }
    let body = &message[IkeHeader::LEN..];
    let min_body = 4 + SKF_EXTRA;
    if body.len() < min_body {
        return Err(IkeError::Truncated { need: min_body, have: body.len() });
    }
    let frag_num = u16::from_be_bytes([body[4], body[5]]);
    let total = u16::from_be_bytes([body[6], body[7]]);
    Ok((frag_num, total))
}

/// Reassemble a set of SKF messages, sealed under `cipher`, into
/// `(first_inner_type, inner_bytes)`. Fragments may arrive in any order; all
/// of `1..=total` must be present exactly once, and every fragment's
/// AEAD tag / CBC ICV must verify.
pub fn reassemble(cipher: SkCipher, messages: &[Vec<u8>], sk_e: &[u8], sk_a: &[u8]) -> Result<(PayloadType, Vec<u8>), IkeError> {
    let mut frags: Vec<Fragment> =
        messages.iter().map(|m| open_fragment(cipher, m, sk_e, sk_a)).collect::<Result<_, _>>()?;
    if frags.is_empty() {
        return Err(IkeError::Crypto("no fragments"));
    }
    let total = frags[0].total;
    if total == 0 || frags.iter().any(|f| f.total != total) {
        return Err(IkeError::Crypto("inconsistent Total Fragments"));
    }
    if frags.len() != total as usize {
        return Err(IkeError::Crypto("wrong number of fragments"));
    }
    frags.sort_by_key(|f| f.frag_num);
    for (i, f) in frags.iter().enumerate() {
        if f.frag_num != (i + 1) as u16 {
            return Err(IkeError::Crypto("duplicate or missing fragment number"));
        }
    }
    let first_inner = PayloadType::from_u8(frags[0].next_payload);
    let mut inner = Vec::new();
    for f in &frags {
        inner.extend_from_slice(&f.content);
    }
    Ok((first_inner, inner))
}

/// The most fragments one message may declare (Total Fragments) for
/// [`Reassembly`] to take it. Far above what any fragmentation threshold
/// produces: even a long certificate chain at the smallest threshold
/// RFC 7383 §2.5.1 recommends (576 bytes) is a few dozen.
pub const MAX_FRAGMENTS: u16 = 256;

/// The most content [`Reassembly`] holds for one message. An IKE message
/// this large does not occur; this bounds what a peer holding the keys can
/// make it keep.
pub const MAX_REASSEMBLED_LEN: usize = 64 * 1024;

/// Which message a fragment belongs to (RFC 7383 §2.6.1, RFC 7296 §2.2,
/// §3.1): its IKE SA, exchange, direction and Message ID -- every field of
/// the IKE header a fragment keeps from the message it was cut from, but
/// the Length and Next Payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageKey {
    pub initiator_spi: u64,
    pub responder_spi: u64,
    pub exchange_type: ExchangeType,
    /// The header's Initiator flag.
    pub initiator: bool,
    /// The header's Response flag.
    pub response: bool,
    pub message_id: u32,
}

impl MessageKey {
    pub fn of(header: &IkeHeader) -> Self {
        Self {
            initiator_spi: header.initiator_spi,
            responder_spi: header.responder_spi,
            exchange_type: header.exchange_type,
            initiator: header.flags.initiator,
            response: header.flags.response,
            message_id: header.message_id,
        }
    }
}

/// What [`Reassembly::accept`] did with one fragment.
#[derive(Debug, PartialEq, Eq)]
pub enum Accepted {
    /// Stored; the others are still to come.
    Stored,
    /// It was the last one: the message's first inner payload type, and its
    /// inner payloads.
    Complete(PayloadType, Vec<u8>),
    /// Discarded, for the reason given, and nothing else changed (RFC 7383
    /// §2.6: "silently discarded").
    Discarded(&'static str),
}

/// The fragments of one message as they come in, in any order (RFC 7383
/// §2.6). A fragment is checked before it can change anything:
///
/// 1. it must belong to the message ([`MessageKey`]) and carry the SKF
///    payload first;
/// 2. its Fragment Number and Total Fragments must be non-zero, the number
///    at most the total, and the total at most [`MAX_FRAGMENTS`] and not
///    smaller than that of the fragments in hand;
/// 3. a fragment with the number and total of one in hand is a replay;
/// 4. it must authenticate (its ICV or AEAD tag).
///
/// Only then does it count: a larger Total than the fragments in hand drops
/// them and starts over with this one (§2.5.2: a sender that refragments
/// makes smaller fragments, so more of them), and it is stored. A forged
/// fragment therefore never takes the place of a genuine one, and never
/// throws genuine ones away. Content beyond [`MAX_REASSEMBLED_LEN`] drops
/// the whole message.
///
/// How long to wait for the rest is the caller's: RFC 7383 §2.6 has it
/// drop an incomplete message after a timeout, as the initiator or
/// responder of the exchange would.
pub struct Reassembly {
    key: MessageKey,
    total: u16,
    /// By Fragment Number: the SKF payload's Next Payload, and the content.
    fragments: BTreeMap<u16, (u8, Vec<u8>)>,
    len: usize,
}

impl Reassembly {
    pub fn new(key: MessageKey) -> Self {
        Self { key, total: 0, fragments: BTreeMap::new(), len: 0 }
    }

    pub fn key(&self) -> MessageKey {
        self.key
    }

    /// Whether no fragment is in hand.
    pub fn is_empty(&self) -> bool {
        self.fragments.is_empty()
    }

    /// Take one fragment, sealed under `cipher` with the sender's `sk_e`
    /// (and, for a classic cipher, `sk_a`). On [`Accepted::Complete`] the
    /// fragments in hand are released, so a late copy of one of them
    /// starts a new message: telling a retransmission of a message already
    /// processed apart (RFC 7383 §2.6.1) is the caller's.
    pub fn accept(&mut self, message: &[u8], cipher: SkCipher, sk_e: &[u8], sk_a: &[u8]) -> Accepted {
        let Ok(header) = IkeHeader::parse(message) else { return Accepted::Discarded("not an IKE message") };
        if MessageKey::of(&header) != self.key {
            return Accepted::Discarded("a fragment of another message");
        }
        let Ok((number, total)) = peek_fragment_header(message) else {
            return Accepted::Discarded("no Encrypted Fragment payload");
        };
        if number == 0 || total == 0 || number > total || total > MAX_FRAGMENTS {
            return Accepted::Discarded("invalid Fragment Number or Total Fragments");
        }
        if total < self.total {
            return Accepted::Discarded("fewer Total Fragments than the fragments in hand");
        }
        if total == self.total && self.fragments.contains_key(&number) {
            return Accepted::Discarded("a replay of a fragment in hand");
        }
        let Ok(fragment) = open_fragment(cipher, message, sk_e, sk_a) else {
            return Accepted::Discarded("does not authenticate");
        };
        if total > self.total {
            self.fragments.clear();
            self.len = 0;
            self.total = total;
        }
        self.len += fragment.content.len();
        if self.len > MAX_REASSEMBLED_LEN {
            self.fragments.clear();
            self.len = 0;
            self.total = 0;
            return Accepted::Discarded("the message is too large");
        }
        self.fragments.insert(number, (fragment.next_payload, fragment.content));
        if self.fragments.len() < usize::from(self.total) {
            return Accepted::Stored;
        }
        let fragments = std::mem::take(&mut self.fragments);
        self.len = 0;
        self.total = 0;
        let first_inner = PayloadType::from_u8(fragments[&1].0);
        let inner = fragments.into_values().flat_map(|(_, content)| content).collect();
        Accepted::Complete(first_inner, inner)
    }
}

/// A fragment's Fragment Number and Total Fragments, once it has
/// authenticated under `cipher` with the sender's keys. For a caller that
/// must tell whether a fragment is genuine without reassembling it, such
/// as one of a request already answered (RFC 7383 §2.6.1).
pub fn verify_fragment(cipher: SkCipher, message: &[u8], sk_e: &[u8], sk_a: &[u8]) -> Result<(u16, u16), IkeError> {
    let fragment = open_fragment(cipher, message, sk_e, sk_a)?;
    Ok((fragment.frag_num, fragment.total))
}

/// `message`, an SK message we built with our own `sk_e`/`sk_a`, cut into
/// fragments (RFC 7383 §2.5) of at most `max_len` bytes each, the IKE
/// header included. `iv_base` seeds the fragments' IVs as in
/// [`build_fragments`], and must be fresh under the key.
pub fn fragment_message(cipher: SkCipher, message: &[u8], sk_e: &[u8], sk_a: &[u8], iv_base: u64, max_len: usize) -> Result<Vec<Vec<u8>>, IkeError> {
    let header = IkeHeader::parse(message)?;
    let (first_inner, inner) = crate::ikev2::sk::open_encrypted(cipher, message, sk_e, sk_a)?;
    // What a fragment adds to its content: the IKE header, the SKF payload
    // with its IV and ICV, and the Pad Length byte (plus, for CBC, padding
    // up to a whole block).
    let (iv_len, block) = if cipher.is_aead() { (IV_LEN, 1) } else { (cipher.block_len(), cipher.block_len()) };
    let room = max_len.saturating_sub(IkeHeader::LEN + 4 + SKF_EXTRA + iv_len + cipher.icv_len());
    let content_per_fragment = (room / block * block).saturating_sub(1);
    if content_per_fragment == 0 {
        return Err(IkeError::Crypto("fragments of that size cannot carry any content"));
    }
    if inner.len().div_ceil(content_per_fragment) > usize::from(MAX_FRAGMENTS) {
        return Err(IkeError::Crypto("the message would need too many fragments"));
    }
    build_fragments(cipher, &header, first_inner, &inner, sk_e, sk_a, iv_base, content_per_fragment)
}

/// The smallest IKE message [`fragment_message`] can put content in under
/// every cipher: AES-CBC with HMAC-SHA2-512-256 takes 28 (IKE header) + 8
/// (SKF header) + 16 (IV) + 32 (ICV) and a whole 16-byte block.
const MIN_FRAGMENT_MESSAGE_LEN: usize = 100;

const IPV4_HEADER_LEN: usize = 20; // without options
const IPV6_HEADER_LEN: usize = 40; // without extension headers
const UDP_HEADER_LEN: usize = 8;
const NON_ESP_MARKER_LEN: usize = 4;

/// The largest whole IP datagram, per family of the outer transport, that
/// a message of ours may travel in. A message larger than that is sent in
/// fragments when the peer negotiated them (RFC 7383), each fragment's
/// datagram within the limit.
///
/// The limit covers the IP and UDP headers and, once the transport has
/// floated to port 4500, the non-ESP marker; [`Self::max_message_len`]
/// takes them off. It is a fixed figure: nothing here discovers the path
/// MTU, and a path narrower than the limit still fragments at the IP layer.
///
/// [`DatagramLimit::DEFAULT`] takes 576 bytes for IPv4 and 1280 for IPv6,
/// the datagram every IPv4 host must accept and the IPv6 minimum link MTU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DatagramLimit {
    ipv4: usize,
    ipv6: usize,
}

/// A [`DatagramLimit`] no IKE fragment fits in, or no IP datagram reaches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("a limit of {requested} bytes for an {family} datagram is outside {min}..={max}")]
pub struct DatagramLimitError {
    family: &'static str,
    requested: usize,
    min: usize,
    max: usize,
}

impl DatagramLimit {
    /// 576 bytes for IPv4, 1280 for IPv6.
    pub const DEFAULT: DatagramLimit = DatagramLimit { ipv4: 576, ipv6: 1280 };

    /// A limit of `ipv4` bytes for an IPv4 datagram and `ipv6` for an IPv6
    /// one, headers included. Each must leave room, past the IP header
    /// (20 or 40 bytes), UDP header and non-ESP marker, for a fragment that
    /// carries content under every cipher, and be no larger than the
    /// family's largest datagram (65535 bytes for IPv4; for IPv6, a
    /// payload of 65535 bytes past its header).
    pub fn new(ipv4: usize, ipv6: usize) -> Result<DatagramLimit, DatagramLimitError> {
        check_family("IPv4", ipv4, IPV4_HEADER_LEN, 65535)?;
        check_family("IPv6", ipv6, IPV6_HEADER_LEN, IPV6_HEADER_LEN + 65535)?;
        Ok(DatagramLimit { ipv4, ipv6 })
    }

    /// The limit for an IPv4 datagram, headers included.
    pub fn ipv4(&self) -> usize {
        self.ipv4
    }

    /// The limit for an IPv6 datagram, headers included.
    pub fn ipv6(&self) -> usize {
        self.ipv6
    }

    /// The largest IKE message, its header included, that fits the limit
    /// when sent to `peer`, with the non-ESP marker in front when
    /// `non_esp_marker`. An IPv4-mapped IPv6 address travels as IPv4.
    pub fn max_message_len(&self, peer: std::net::IpAddr, non_esp_marker: bool) -> usize {
        let v4 = match peer {
            std::net::IpAddr::V4(_) => true,
            std::net::IpAddr::V6(v6) => v6.to_ipv4_mapped().is_some(),
        };
        let (total, ip_header) = if v4 { (self.ipv4, IPV4_HEADER_LEN) } else { (self.ipv6, IPV6_HEADER_LEN) };
        let marker = if non_esp_marker { NON_ESP_MARKER_LEN } else { 0 };
        total - ip_header - UDP_HEADER_LEN - marker
    }
}

impl Default for DatagramLimit {
    fn default() -> Self {
        DatagramLimit::DEFAULT
    }
}

fn check_family(family: &'static str, requested: usize, ip_header: usize, max: usize) -> Result<(), DatagramLimitError> {
    let min = ip_header + UDP_HEADER_LEN + NON_ESP_MARKER_LEN + MIN_FRAGMENT_MESSAGE_LEN;
    if (min..=max).contains(&requested) {
        Ok(())
    } else {
        Err(DatagramLimitError { family, requested, min, max })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::IntegAlgorithm;
    use crate::ikev2::message::{ExchangeType, Flags};

    fn header() -> IkeHeader {
        IkeHeader {
            initiator_spi: 0x1111_2222_3333_4444,
            responder_spi: 0x5555_6666_7777_8888,
            next_payload: PayloadType::NoNext,
            major_version: 2,
            minor_version: 0,
            exchange_type: ExchangeType::IkeAuth,
            flags: Flags { initiator: true, version: false, response: false },
            message_id: 1,
            length: 0,
        }
    }

    fn aead_ciphers() -> Vec<SkCipher> {
        vec![SkCipher::Aes128Gcm, SkCipher::Aes192Gcm, SkCipher::Aes256Gcm, SkCipher::ChaCha20Poly1305]
    }

    fn cbc_ciphers() -> Vec<SkCipher> {
        use IntegAlgorithm::*;
        vec![
            SkCipher::Aes128Cbc(HmacSha2_256_128),
            SkCipher::Aes192Cbc(HmacSha1_96),
            SkCipher::Aes256Cbc(HmacSha2_512_256),
            SkCipher::TripleDesCbc(HmacMd5_96),
        ]
    }

    fn keys_for(cipher: SkCipher) -> (Vec<u8>, Vec<u8>) {
        let sk_e = vec![0x33u8; cipher.key_len() + cipher.salt_len()];
        let sk_a = cipher.integ_algorithm().map(|i| vec![0x55u8; i.key_len()]).unwrap_or_default();
        (sk_e, sk_a)
    }

    #[test]
    fn fragment_and_reassemble_roundtrip_any_order_every_aead_cipher() {
        for cipher in aead_ciphers() {
            let (sk_e, sk_a) = keys_for(cipher);
            let inner: Vec<u8> = (0..=200u8).collect(); // 201 bytes
            let frags = build_fragments(cipher, &header(), PayloadType::IdInitiator, &inner, &sk_e, &sk_a, 1000, 30).unwrap();
            assert_eq!(frags.len(), 7, "{cipher:?}");

            for f in &frags {
                assert_eq!(IkeHeader::parse(f).unwrap().next_payload, PayloadType::EncryptedFragment);
            }

            let mut shuffled = frags.clone();
            shuffled.reverse();
            let (first, out) = reassemble(cipher, &shuffled, &sk_e, &sk_a).unwrap();
            assert_eq!(first, PayloadType::IdInitiator, "{cipher:?}");
            assert_eq!(out, inner, "{cipher:?}");
        }
    }

    #[test]
    fn fragment_and_reassemble_roundtrip_any_order_every_cbc_cipher() {
        for cipher in cbc_ciphers() {
            let (sk_e, sk_a) = keys_for(cipher);
            let inner: Vec<u8> = (0..=200u8).collect(); // 201 bytes
            let frags = build_fragments(cipher, &header(), PayloadType::IdInitiator, &inner, &sk_e, &sk_a, 1000, 30).unwrap();
            assert!(frags.len() > 1, "{cipher:?}");

            for f in &frags {
                assert_eq!(IkeHeader::parse(f).unwrap().next_payload, PayloadType::EncryptedFragment);
            }

            let mut shuffled = frags.clone();
            shuffled.reverse();
            let (first, out) = reassemble(cipher, &shuffled, &sk_e, &sk_a).unwrap();
            assert_eq!(first, PayloadType::IdInitiator, "{cipher:?}");
            assert_eq!(out, inner, "{cipher:?}");
        }
    }

    #[test]
    fn single_fragment_when_it_fits() {
        let sk_e = vec![1u8; 36];
        let inner = vec![9u8; 10];
        let frags = build_fragments(SkCipher::Aes256Gcm, &header(), PayloadType::Nonce, &inner, &sk_e, &[], 5, 1000).unwrap();
        assert_eq!(frags.len(), 1);
        let (first, out) = reassemble(SkCipher::Aes256Gcm, &frags, &sk_e, &[]).unwrap();
        assert_eq!(first, PayloadType::Nonce);
        assert_eq!(out, inner);
    }

    #[test]
    fn missing_fragment_is_rejected() {
        let sk_e = vec![2u8; 36];
        let inner = vec![7u8; 100];
        let mut frags = build_fragments(SkCipher::Aes256Gcm, &header(), PayloadType::IdInitiator, &inner, &sk_e, &[], 1, 30).unwrap();
        frags.pop(); // drop the last fragment
        assert!(reassemble(SkCipher::Aes256Gcm, &frags, &sk_e, &[]).is_err());
    }

    #[test]
    fn tampered_fragment_fails_authentication() {
        let sk_e = vec![4u8; 36];
        let inner = vec![3u8; 80];
        let mut frags = build_fragments(SkCipher::Aes256Gcm, &header(), PayloadType::IdInitiator, &inner, &sk_e, &[], 1, 30).unwrap();
        let last = frags[0].len() - 1;
        frags[0][last] ^= 1; // corrupt a tag byte in the first fragment
        assert_eq!(reassemble(SkCipher::Aes256Gcm, &frags, &sk_e, &[]).unwrap_err(), IkeError::BadIntegrity);
    }

    #[test]
    fn cbc_tampered_fragment_fails_authentication() {
        let cipher = SkCipher::Aes256Cbc(IntegAlgorithm::HmacSha2_512_256);
        let (sk_e, sk_a) = keys_for(cipher);
        let inner = vec![3u8; 80];
        let mut frags = build_fragments(cipher, &header(), PayloadType::IdInitiator, &inner, &sk_e, &sk_a, 1, 30).unwrap();
        let last = frags[0].len() - 1;
        frags[0][last] ^= 1; // corrupt an ICV byte in the first fragment
        assert_eq!(reassemble(cipher, &frags, &sk_e, &sk_a).unwrap_err(), IkeError::BadIntegrity);
    }

    #[test]
    fn peek_fragment_header_reads_number_and_total_without_the_keys() {
        let sk_e = vec![1u8; 36];
        let inner: Vec<u8> = (0..=200u8).collect();
        let frags = build_fragments(SkCipher::Aes256Gcm, &header(), PayloadType::IdInitiator, &inner, &sk_e, &[], 1, 30).unwrap();
        assert!(frags.len() > 1);
        for (i, f) in frags.iter().enumerate() {
            let (num, total) = peek_fragment_header(f).unwrap();
            assert_eq!(num, (i + 1) as u16);
            assert_eq!(total, frags.len() as u16);
        }
    }

    #[test]
    fn peek_fragment_header_rejects_a_non_skf_message() {
        let mut hdr = header();
        hdr.next_payload = PayloadType::Encrypted;
        assert!(peek_fragment_header(&hdr.to_bytes()).is_err());
    }

    #[test]
    fn a_fragment_sealed_under_a_different_cipher_family_fails_to_open() {
        // FragNum/Total are folded into what each framing authenticates, but
        // this also proves the two framings aren't interchangeable at the
        // wire-parsing level: an AEAD fragment fed to the CBC path (or vice
        // versa) must not silently misparse.
        let sk_e_gcm = vec![6u8; 36];
        let frags = build_fragments(SkCipher::Aes256Gcm, &header(), PayloadType::IdInitiator, &[1, 2, 3], &sk_e_gcm, &[], 1, 30).unwrap();
        let cbc = SkCipher::Aes256Cbc(IntegAlgorithm::HmacSha2_512_256);
        let (sk_e_cbc, sk_a_cbc) = keys_for(cbc);
        assert!(reassemble(cbc, &frags, &sk_e_cbc, &sk_a_cbc).is_err());
    }

    fn all_ciphers() -> Vec<SkCipher> {
        aead_ciphers().into_iter().chain(cbc_ciphers()).collect()
    }

    /// `inner` under [`header`] as fragments of `per` bytes of content.
    fn split(cipher: SkCipher, inner: &[u8], per: usize, iv_base: u64) -> Vec<Vec<u8>> {
        let (sk_e, sk_a) = keys_for(cipher);
        build_fragments(cipher, &header(), PayloadType::IdInitiator, inner, &sk_e, &sk_a, iv_base, per).unwrap()
    }

    fn reassembly() -> Reassembly {
        Reassembly::new(MessageKey::of(&header()))
    }

    fn forged(mut msg: Vec<u8>) -> Vec<u8> {
        *msg.last_mut().unwrap() ^= 1;
        msg
    }

    /// Where the SKF payload's Fragment Number and Total Fragments sit.
    const NUMBER_AT: usize = IkeHeader::LEN + 4;
    const TOTAL_AT: usize = IkeHeader::LEN + 6;

    fn with_u16(mut msg: Vec<u8>, at: usize, value: u16) -> Vec<u8> {
        msg[at..at + 2].copy_from_slice(&value.to_be_bytes());
        msg
    }

    #[test]
    fn reassembly_completes_in_any_order_and_a_replay_is_discarded() {
        for cipher in all_ciphers() {
            let (sk_e, sk_a) = keys_for(cipher);
            let inner: Vec<u8> = (0..=200u8).collect();
            let frags = split(cipher, &inner, 50, 10);
            assert_eq!(frags.len(), 5);
            let mut r = reassembly();
            for f in frags[1..].iter().rev() {
                assert_eq!(r.accept(f, cipher, &sk_e, &sk_a), Accepted::Stored, "{cipher:?}");
            }
            assert_eq!(r.accept(&frags[4], cipher, &sk_e, &sk_a), Accepted::Discarded("a replay of a fragment in hand"));
            assert_eq!(r.accept(&frags[0], cipher, &sk_e, &sk_a), Accepted::Complete(PayloadType::IdInitiator, inner.clone()));
            assert!(r.is_empty(), "a completed message is released");
        }
    }

    /// RFC 7383 §2.6: the ICV is checked before a fragment can change
    /// anything. A forged fragment 1 ahead of the real one does not hold
    /// its place; a forged fragment with a larger Total does not throw away
    /// the genuine ones in hand.
    #[test]
    fn a_forged_fragment_neither_takes_a_place_nor_restarts_the_reassembly() {
        for cipher in all_ciphers() {
            let (sk_e, sk_a) = keys_for(cipher);
            let inner = vec![0x42u8; 150];
            let frags = split(cipher, &inner, 50, 10);
            let finer = split(cipher, &inner, 30, 90);
            assert_eq!((frags.len(), finer.len()), (3, 5));
            let mut r = reassembly();
            assert_eq!(r.accept(&forged(frags[0].clone()), cipher, &sk_e, &sk_a), Accepted::Discarded("does not authenticate"));
            assert!(r.is_empty(), "{cipher:?}");
            assert_eq!(r.accept(&frags[0], cipher, &sk_e, &sk_a), Accepted::Stored);
            assert_eq!(r.accept(&frags[1], cipher, &sk_e, &sk_a), Accepted::Stored);
            assert_eq!(r.accept(&forged(finer[0].clone()), cipher, &sk_e, &sk_a), Accepted::Discarded("does not authenticate"));
            assert_eq!(r.accept(&frags[2], cipher, &sk_e, &sk_a), Accepted::Complete(PayloadType::IdInitiator, inner.clone()));
        }
    }

    /// RFC 7383 §2.6 (and §2.5.2: a sender that fragments again makes more,
    /// smaller fragments): an authentic fragment with a larger Total drops
    /// the fragments in hand and starts over; one with a smaller Total is
    /// discarded.
    #[test]
    fn a_larger_total_restarts_the_reassembly_and_a_smaller_one_is_discarded() {
        let cipher = SkCipher::Aes256Gcm;
        let (sk_e, sk_a) = keys_for(cipher);
        let inner = vec![0x42u8; 150];
        let coarse = split(cipher, &inner, 75, 10);
        let fine = split(cipher, &inner, 50, 90);
        assert_eq!((coarse.len(), fine.len()), (2, 3));

        let mut r = reassembly();
        assert_eq!(r.accept(&coarse[0], cipher, &sk_e, &sk_a), Accepted::Stored);
        assert_eq!(r.accept(&fine[0], cipher, &sk_e, &sk_a), Accepted::Stored);
        assert_eq!(r.accept(&coarse[1], cipher, &sk_e, &sk_a), Accepted::Discarded("fewer Total Fragments than the fragments in hand"));
        assert_eq!(r.accept(&fine[1], cipher, &sk_e, &sk_a), Accepted::Stored);
        assert_eq!(r.accept(&fine[2], cipher, &sk_e, &sk_a), Accepted::Complete(PayloadType::IdInitiator, inner));
    }

    /// RFC 7383 §2.6.1, RFC 7296 §2.2: a fragment belongs to one message --
    /// one IKE SA, exchange, direction and Message ID.
    #[test]
    fn an_authentic_fragment_of_another_message_is_discarded() {
        let cipher = SkCipher::Aes256Gcm;
        let (sk_e, sk_a) = keys_for(cipher);
        let variants: [fn(&mut IkeHeader); 6] = [
            |h| h.initiator_spi ^= 1,
            |h| h.responder_spi ^= 1,
            |h| h.exchange_type = ExchangeType::Informational,
            |h| h.flags.initiator = false,
            |h| h.flags.response = true,
            |h| h.message_id += 1,
        ];
        for (i, variant) in variants.into_iter().enumerate() {
            let mut other = header();
            variant(&mut other);
            let frag = build_fragments(cipher, &other, PayloadType::IdInitiator, &[7u8; 60], &sk_e, &sk_a, 5, 30).unwrap().remove(0);
            let mut r = reassembly();
            assert_eq!(r.accept(&frag, cipher, &sk_e, &sk_a), Accepted::Discarded("a fragment of another message"), "variant {i}");
            assert!(r.is_empty());
        }
    }

    /// RFC 7383 §2.6: Fragment Number and Total Fragments must be non-zero
    /// and the number at most the total; a Total beyond [`MAX_FRAGMENTS`]
    /// is not taken either. None of these is even authenticated.
    #[test]
    fn invalid_fragment_numbers_and_totals_are_discarded() {
        let cipher = SkCipher::Aes256Gcm;
        let (sk_e, sk_a) = keys_for(cipher);
        let frag = split(cipher, &[7u8; 60], 30, 5).remove(0);
        for bad in [
            with_u16(frag.clone(), NUMBER_AT, 0),
            with_u16(frag.clone(), TOTAL_AT, 0),
            with_u16(frag.clone(), NUMBER_AT, 3),
            with_u16(with_u16(frag.clone(), NUMBER_AT, MAX_FRAGMENTS + 1), TOTAL_AT, MAX_FRAGMENTS + 1),
        ] {
            let mut r = reassembly();
            assert_eq!(r.accept(&bad, cipher, &sk_e, &sk_a), Accepted::Discarded("invalid Fragment Number or Total Fragments"));
            assert!(r.is_empty());
        }
    }

    /// A message whose fragments carry more than [`MAX_REASSEMBLED_LEN`]
    /// is dropped whole, however authentic.
    #[test]
    fn a_message_beyond_the_size_cap_is_dropped_whole() {
        let cipher = SkCipher::Aes256Gcm;
        let (sk_e, sk_a) = keys_for(cipher);
        let frags = split(cipher, &vec![1u8; MAX_REASSEMBLED_LEN + 1], 300, 5);
        assert!(frags.len() <= usize::from(MAX_FRAGMENTS));
        let mut r = reassembly();
        let (last, rest) = frags.split_last().unwrap();
        for f in rest {
            assert_eq!(r.accept(f, cipher, &sk_e, &sk_a), Accepted::Stored);
        }
        assert_eq!(r.accept(last, cipher, &sk_e, &sk_a), Accepted::Discarded("the message is too large"));
        assert!(r.is_empty());
    }

    #[test]
    fn verify_fragment_reads_number_and_total_only_from_an_authentic_fragment() {
        for cipher in all_ciphers() {
            let (sk_e, sk_a) = keys_for(cipher);
            let frags = split(cipher, &[7u8; 90], 30, 5);
            assert_eq!(verify_fragment(cipher, &frags[1], &sk_e, &sk_a).unwrap(), (2, 3));
            assert!(verify_fragment(cipher, &forged(frags[1].clone()), &sk_e, &sk_a).is_err(), "{cipher:?}");
        }
    }

    /// [`fragment_message`] cuts a whole `SK` message into fragments no
    /// larger than asked, which reassemble to its payloads.
    #[test]
    fn fragment_message_keeps_every_fragment_within_the_size_asked() {
        for cipher in all_ciphers() {
            let (sk_e, sk_a) = keys_for(cipher);
            let inner: Vec<u8> = (0..2000u32).map(|i| i as u8).collect();
            let whole = crate::ikev2::sk::build_encrypted(cipher, header(), PayloadType::IdInitiator, &inner, &sk_e, &sk_a, &[1u8; 8]).unwrap();
            for max_len in [200, 576, 1280] {
                let frags = fragment_message(cipher, &whole, &sk_e, &sk_a, 7, max_len).unwrap();
                assert!(frags.len() > 1, "{cipher:?} {max_len}");
                assert!(frags.iter().all(|f| f.len() <= max_len), "{cipher:?} {max_len}");
                assert_eq!(reassemble(cipher, &frags, &sk_e, &sk_a).unwrap(), (PayloadType::IdInitiator, inner.clone()));
            }
            assert!(fragment_message(cipher, &whole, &sk_e, &sk_a, 7, 60).is_err(), "no room for any content");
        }
    }

    /// Every cipher, under every integrity algorithm, fragments a message
    /// at [`MIN_FRAGMENT_MESSAGE_LEN`], the floor [`DatagramLimit::new`]
    /// is built on; the costliest cannot do with a byte less.
    #[test]
    fn every_cipher_fragments_at_the_smallest_message_a_limit_allows() {
        use IntegAlgorithm::*;
        let integs = [HmacMd5_96, HmacSha1_96, HmacSha2_256_128, HmacSha2_384_192, HmacSha2_512_256];
        let ciphers = aead_ciphers().into_iter().chain(integs.iter().flat_map(|&i| {
            [SkCipher::Aes128Cbc(i), SkCipher::Aes192Cbc(i), SkCipher::Aes256Cbc(i), SkCipher::TripleDesCbc(i)]
        }));
        for cipher in ciphers {
            let (sk_e, sk_a) = keys_for(cipher);
            let inner = vec![9u8; 300];
            let whole = crate::ikev2::sk::build_encrypted(cipher, header(), PayloadType::IdInitiator, &inner, &sk_e, &sk_a, &[1u8; 8]).unwrap();
            let frags = fragment_message(cipher, &whole, &sk_e, &sk_a, 7, MIN_FRAGMENT_MESSAGE_LEN).unwrap();
            assert!(frags.iter().all(|f| f.len() <= MIN_FRAGMENT_MESSAGE_LEN), "{cipher:?}");
            assert_eq!(reassemble(cipher, &frags, &sk_e, &sk_a).unwrap().1, inner, "{cipher:?}");
        }
        let cipher = SkCipher::Aes256Cbc(HmacSha2_512_256);
        let (sk_e, sk_a) = keys_for(cipher);
        let whole = crate::ikev2::sk::build_encrypted(cipher, header(), PayloadType::IdInitiator, &[9u8; 300], &sk_e, &sk_a, &[1u8; 8]).unwrap();
        assert!(fragment_message(cipher, &whole, &sk_e, &sk_a, 7, MIN_FRAGMENT_MESSAGE_LEN - 1).is_err());
    }

    #[test]
    fn the_default_limit_is_576_bytes_for_ipv4_and_1280_for_ipv6() {
        assert_eq!(DatagramLimit::default(), DatagramLimit::DEFAULT);
        assert_eq!((DatagramLimit::DEFAULT.ipv4(), DatagramLimit::DEFAULT.ipv6()), (576, 1280));
        assert_eq!(DatagramLimit::new(576, 1280), Ok(DatagramLimit::DEFAULT));
    }

    /// A limit leaves room for a fragment behind the IP and UDP headers
    /// and the non-ESP marker, and fits the family's largest datagram.
    #[test]
    fn a_limit_no_fragment_fits_in_or_no_datagram_reaches_is_refused() {
        assert!(DatagramLimit::new(132, 152).is_ok());
        assert!(DatagramLimit::new(65535, 65575).is_ok());
        let low4 = DatagramLimit::new(131, 1280).unwrap_err();
        assert_eq!(low4.to_string(), "a limit of 131 bytes for an IPv4 datagram is outside 132..=65535");
        let low6 = DatagramLimit::new(576, 151).unwrap_err();
        assert_eq!(low6.to_string(), "a limit of 151 bytes for an IPv6 datagram is outside 152..=65575");
        assert!(DatagramLimit::new(65536, 1280).is_err());
        assert!(DatagramLimit::new(576, 65576).is_err());
        assert!(DatagramLimit::new(0, 0).is_err());
    }

    /// What is left for the IKE message: the limit of the outer family,
    /// less its IP header, the UDP header and, once floated, the marker.
    #[test]
    fn the_message_gets_what_the_family_limit_leaves_past_the_headers() {
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
        let limit = DatagramLimit::new(600, 1400).unwrap();
        let v4 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let v6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let mapped = IpAddr::V6(Ipv4Addr::new(192, 0, 2, 1).to_ipv6_mapped());
        assert_eq!(limit.max_message_len(v4, false), 600 - 20 - 8);
        assert_eq!(limit.max_message_len(v4, true), 600 - 20 - 8 - 4);
        assert_eq!(limit.max_message_len(v6, false), 1400 - 40 - 8);
        assert_eq!(limit.max_message_len(v6, true), 1400 - 40 - 8 - 4);
        assert_eq!(limit.max_message_len(mapped, true), 600 - 20 - 8 - 4, "an IPv4-mapped peer travels as IPv4");
        assert_eq!(DatagramLimit::DEFAULT.max_message_len(v4, true), 544);
        assert_eq!(DatagramLimit::DEFAULT.max_message_len(v6, false), 1232);
        // The smallest limit still leaves room for a fragment.
        let floor = DatagramLimit::new(132, 152).unwrap();
        assert_eq!(floor.max_message_len(v4, true), MIN_FRAGMENT_MESSAGE_LEN);
        assert_eq!(floor.max_message_len(v6, true), MIN_FRAGMENT_MESSAGE_LEN);
    }
}
