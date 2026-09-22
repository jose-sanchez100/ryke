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

use crate::error::IkeError;
use crate::ikev2::message::{IkeHeader, PayloadType};
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
}
