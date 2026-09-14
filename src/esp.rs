//! Userspace ESP (RFC 4303) in tunnel mode, algorithm-agile.
//!
//! `ryke` can encrypt and decrypt the tunneled IP packets itself — it does not
//! have to use the OS kernel's IPsec stack (though `free-vpn-v2`'s live data
//! plane does, via kernel XFRM; this module backs the test/interop harnesses
//! and any userspace-ESP consumer). An ESP packet on the wire:
//!
//! ```text
//! SPI(4) | SeqNum(4) | IV | ciphertext | ICV
//! ```
//!
//! where the ciphertext covers `{ inner IP packet | padding | pad length |
//! next header }` (RFC 4303 §2.4, same trailer for every cipher below).
//!
//! - **AEAD** (AES-GCM-16 128/192/256, ChaCha20-Poly1305): IV is 8 bytes
//!   (explicit), ICV is the 16-byte AEAD tag folded in by the cipher itself.
//!   The nonce is `salt(4) ‖ IV(8)`, salt from the CHILD-SA key material's
//!   trailing 4 bytes; the AEAD associated data is `SPI | SeqNum`.
//! - **Classic** (AES-CBC 128/192/256, 3DES-CBC, paired with a separate
//!   [`crate::crypto::IntegAlgorithm`]): IV is the cipher's block size,
//!   derived per-packet from the (secret) encryption key + SPI + sequence
//!   number via SHA-256 (see [`cbc_packet_iv`]) rather than drawn from an
//!   RNG — `EspSa::seal` has no entropy-source parameter, and a value that's
//!   a keyed hash of already-unique-per-key inputs (SPI+seq never repeat
//!   under one key) is exactly as unpredictable to an attacker without the
//!   key as fresh randomness would be, which is what CBC's IV requirement
//!   (unique + unpredictable) actually needs. The ICV is
//!   `IntegAlgorithm::compute` over `SPI | SeqNum | IV | ciphertext`
//!   (RFC 4303 §2.8: everything but the ICV field itself).
//!
//! Both cipher families reuse [`crate::ikev2::sk::SkCipher`] — the same
//! ENCR(+INTEG) tag the `SK{}` payload uses — since the algorithm catalog
//! (RFC 7296 §3.3.2 transform IDs) and the low-level AEAD/CBC primitives are
//! identical; only the surrounding packet framing (ESP header vs. IKE
//! header) differs.

use crate::crypto::{derive_child_keys, derive_child_keys_pfs, ChildKeys, IntegAlgorithm};
use crate::error::IkeError;
use crate::ikev2::sk::{aead_nonce, aead_open_dispatch, aead_seal_dispatch, cbc_decrypt, cbc_encrypt, SkCipher};
use crate::role::Role;

const SALT_LEN: usize = 4;
const IV_LEN: usize = 8; // AEAD explicit IV
const ESP_HEADER_LEN: usize = 8; // SPI + SeqNum

/// Next Header values for tunnel-mode inner packets.
pub mod next_header {
    pub const IPV4: u8 = 4;
    pub const IPV6: u8 = 41;
}

/// Constant-time byte-slice equality — avoids a timing side channel verifying
/// a classic cipher's HMAC ICV.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Per-packet CBC IV: `SHA-256(enc_key | SPI | seq | counter)`, truncated to
/// `block` bytes. See the module doc for why this (rather than an RNG call)
/// is the right source for a classic ESP cipher's IV here.
fn cbc_packet_iv(enc_key: &[u8], spi: u32, seq: u32, block: usize) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut out = Vec::with_capacity(block + 32);
    let mut counter: u8 = 0;
    while out.len() < block {
        let mut h = Sha256::new();
        h.update(b"ryke-esp-cbc-iv");
        h.update(enc_key);
        h.update(spi.to_be_bytes());
        h.update(seq.to_be_bytes());
        h.update([counter]);
        out.extend_from_slice(&h.finalize());
        counter += 1;
    }
    out.truncate(block);
    out
}

/// One direction of an ESP security association: tunnel mode, non-ESN, under
/// a negotiated [`SkCipher`]. Holds the SPI to stamp on outbound packets, the
/// key material, and the outbound sequence counter.
pub struct EspSa {
    spi: u32,
    cipher: SkCipher,
    /// Raw encryption key (no salt — kept separately below).
    enc_key: Vec<u8>,
    /// AEAD salt (4 bytes); empty for a classic cipher.
    salt: Vec<u8>,
    /// Classic-cipher integrity key; empty for AEAD.
    integ_key: Vec<u8>,
    seq: u32,
    /// Anti-replay state (RFC 4303 §3.4.3), inbound side only: highest
    /// sequence number accepted so far, plus a 64-wide bitmap of the
    /// `replay_highest - 63 ..= replay_highest` window (bit 0 = highest).
    /// Outbound `EspSa`s never consult this -- only `open()` does.
    replay_highest: u32,
    replay_window: u64,
}

impl EspSa {
    /// `key_material` is 36 bytes: a 32-byte AES-256 key + a 4-byte salt, as
    /// produced by [`crate::crypto::derive_child_keys`] for the fixed
    /// AES-256-GCM shape every caller of this constructor still uses today
    /// (`ikev1::quick`, `examples/ike_client_eap_fortigate`). Prefer
    /// [`Self::new_with_cipher`] for any other [`SkCipher`].
    pub fn new(spi: u32, key_material: &[u8]) -> Result<Self, IkeError> {
        Self::new_with_cipher(spi, SkCipher::Aes256Gcm, key_material, &[])
    }

    /// Build one direction of an ESP SA under an arbitrary negotiated
    /// `cipher`. `enc_material` is the encryption key, plus (for an AEAD
    /// cipher) its trailing 4-byte salt — `cipher.key_len() +
    /// cipher.salt_len()` bytes total. `integ_key` is the separate
    /// integrity key a classic cipher needs (`cipher.integ_algorithm()`'s
    /// `key_len()` bytes; ignored, and may be empty, for AEAD).
    pub fn new_with_cipher(spi: u32, cipher: SkCipher, enc_material: &[u8], integ_key: &[u8]) -> Result<Self, IkeError> {
        let want_enc = cipher.key_len() + cipher.salt_len();
        if enc_material.len() != want_enc {
            return Err(IkeError::Crypto("ESP encryption key material has the wrong length for this cipher"));
        }
        if let Some(integ) = cipher.integ_algorithm() {
            if integ_key.len() != integ.key_len() {
                return Err(IkeError::Crypto("ESP integrity key has the wrong length for this cipher"));
            }
        }
        let (enc_key, salt) = enc_material.split_at(cipher.key_len());
        Ok(EspSa {
            spi,
            cipher,
            enc_key: enc_key.to_vec(),
            salt: salt.to_vec(),
            integ_key: integ_key.to_vec(),
            seq: 0,
            replay_highest: 0,
            replay_window: 0,
        })
    }

    pub fn spi(&self) -> u32 {
        self.spi
    }

    /// The cipher this SA was negotiated with.
    pub fn cipher(&self) -> SkCipher {
        self.cipher
    }

    /// The encryption key material in [`Self::new_with_cipher`]'s own input
    /// shape: the raw key, plus (for an AEAD cipher) its trailing salt --
    /// `cipher().key_len() + cipher().salt_len()` bytes. General-cipher
    /// counterpart to [`Self::key_material`] (which is AES-256-GCM-only).
    pub fn enc_material(&self) -> Vec<u8> {
        let mut out = self.enc_key.clone();
        out.extend_from_slice(&self.salt);
        out
    }

    /// The separate integrity key for a classic (non-AEAD) cipher; empty for
    /// AEAD, which has none. General-cipher counterpart to the integ half of
    /// [`Self::key_material`]'s fixed AES-256-GCM shape (which has none at
    /// all, since GCM is AEAD).
    pub fn integ_key(&self) -> &[u8] {
        &self.integ_key
    }

    /// The raw key+salt material this SA was derived from (32-byte AES key +
    /// 4-byte GCM salt, RFC 4106 layout) — for a consumer that hands packets
    /// to the kernel via XFRM instead of this struct's own `seal`/`open`.
    /// AES-256-GCM only; panics if this SA was built with a different cipher
    /// (a caller using [`Self::new_with_cipher`] for a non-default cipher
    /// already has its own key material and has no reason to call this).
    pub fn key_material(&self) -> [u8; 32 + SALT_LEN] {
        assert_eq!(self.cipher, SkCipher::Aes256Gcm, "key_material() is AES-256-GCM-only");
        let mut out = [0u8; 32 + SALT_LEN];
        out[..32].copy_from_slice(&self.enc_key);
        out[32..].copy_from_slice(&self.salt);
        out
    }

    fn nonce(&self, iv: &[u8; IV_LEN]) -> [u8; SALT_LEN + IV_LEN] {
        aead_nonce(&self.salt, iv)
    }

    /// Encrypt an inner IP packet into an ESP packet (tunnel mode). Advances the
    /// sequence number, which must never repeat under one key.
    pub fn seal(&mut self, inner: &[u8], next_header: u8) -> Result<Vec<u8>, IkeError> {
        self.seq = self
            .seq
            .checked_add(1)
            .ok_or(IkeError::Crypto("ESP sequence number exhausted; rekey required"))?;
        let seq = self.seq;

        // plaintext = inner | padding | pad_len | next_header, padded so that
        // (inner + padding + 2) is a multiple of 4 (RFC 4303 §2.4) for AEAD,
        // or a multiple of the cipher's block size for a classic cipher.
        let align = if self.cipher.is_aead() { 4 } else { self.cipher.block_len() };
        let unpadded = inner.len() + 2;
        let pad = (align - (unpadded % align)) % align;
        let mut plaintext = Vec::with_capacity(inner.len() + pad + 2);
        plaintext.extend_from_slice(inner);
        for i in 0..pad {
            plaintext.push((i + 1) as u8); // ESP padding is 1, 2, 3, …
        }
        plaintext.push(pad as u8);
        plaintext.push(next_header);

        let mut aad = [0u8; ESP_HEADER_LEN];
        aad[..4].copy_from_slice(&self.spi.to_be_bytes());
        aad[4..].copy_from_slice(&seq.to_be_bytes());

        let (iv, ct_and_tag): (Vec<u8>, Vec<u8>) = if self.cipher.is_aead() {
            let iv = (seq as u64).to_be_bytes();
            let ct = aead_seal_dispatch(self.cipher, &self.enc_key, &self.nonce(&iv), &aad, &plaintext)?;
            (iv.to_vec(), ct)
        } else {
            let iv = cbc_packet_iv(&self.enc_key, self.spi, seq, self.cipher.block_len());
            let ct = cbc_encrypt(self.cipher, &self.enc_key, &iv, &plaintext)?;
            let integ = self.cipher.integ_algorithm().expect("classic cipher has an integ algorithm");
            let mut mac_input = Vec::with_capacity(aad.len() + iv.len() + ct.len());
            mac_input.extend_from_slice(&aad);
            mac_input.extend_from_slice(&iv);
            mac_input.extend_from_slice(&ct);
            let icv = integ.compute(&self.integ_key, &mac_input);
            let mut ct_and_icv = ct;
            ct_and_icv.extend_from_slice(&icv);
            (iv, ct_and_icv)
        };

        let mut out = Vec::with_capacity(ESP_HEADER_LEN + iv.len() + ct_and_tag.len());
        out.extend_from_slice(&aad);
        out.extend_from_slice(&iv);
        out.extend_from_slice(&ct_and_tag);
        Ok(out)
    }

    /// RFC 4303 §3.4.3 sliding-replay-window check, against `seq` alone (no
    /// state mutation) -- called *before* decrypting, so a forged packet
    /// with a stale/reused sequence number is rejected without spending a
    /// crypto verification on it.
    fn replay_check(&self, seq: u32) -> Result<(), IkeError> {
        if seq == 0 {
            return Err(IkeError::Crypto("ESP replay detected"));
        }
        if seq > self.replay_highest {
            return Ok(());
        }
        let diff = self.replay_highest - seq;
        if diff >= 64 {
            return Err(IkeError::Crypto("ESP replay detected"));
        }
        if self.replay_window & (1 << diff) != 0 {
            return Err(IkeError::Crypto("ESP replay detected"));
        }
        Ok(())
    }

    /// Records `seq` as accepted -- only called *after* the packet's
    /// ICV/AEAD tag has verified, so an attacker can't burn valid sequence
    /// numbers with forged packets.
    fn replay_advance(&mut self, seq: u32) {
        if seq > self.replay_highest {
            let shift = seq - self.replay_highest;
            self.replay_window = if shift >= 64 { 0 } else { self.replay_window << shift };
            self.replay_window |= 1;
            self.replay_highest = seq;
        } else {
            let diff = self.replay_highest - seq;
            self.replay_window |= 1 << diff;
        }
    }

    /// Decrypt an ESP packet, returning the inner IP packet and its Next Header.
    /// The packet's SPI must match this SA. Enforces the RFC 4303 §3.4.3
    /// anti-replay window; call this only on the inbound `EspSa` of a live
    /// session (a fresh one built for a one-off decrypt, e.g. in a test, has
    /// an empty window and so accepts any single packet once).
    pub fn open(&mut self, packet: &[u8]) -> Result<(Vec<u8>, u8), IkeError> {
        let iv_len = if self.cipher.is_aead() { IV_LEN } else { self.cipher.block_len() };
        let icv_len = self.cipher.icv_len();
        let min = ESP_HEADER_LEN + iv_len + icv_len;
        if packet.len() < min {
            return Err(IkeError::Truncated { need: min, have: packet.len() });
        }
        let spi = u32::from_be_bytes(packet[0..4].try_into().unwrap());
        if spi != self.spi {
            return Err(IkeError::Crypto("ESP SPI does not match this SA"));
        }
        let seq = u32::from_be_bytes(packet[4..8].try_into().unwrap());
        self.replay_check(seq)?;
        let aad = &packet[0..ESP_HEADER_LEN]; // SPI | SeqNum
        let iv = &packet[ESP_HEADER_LEN..ESP_HEADER_LEN + iv_len];
        let ct_and_tag = &packet[ESP_HEADER_LEN + iv_len..];

        let plaintext = if self.cipher.is_aead() {
            let iv_arr: [u8; IV_LEN] = iv.try_into().unwrap();
            aead_open_dispatch(self.cipher, &self.enc_key, &self.nonce(&iv_arr), aad, ct_and_tag)?
        } else {
            if ct_and_tag.len() < icv_len {
                return Err(IkeError::Truncated { need: icv_len, have: ct_and_tag.len() });
            }
            let ct = &ct_and_tag[..ct_and_tag.len() - icv_len];
            let icv = &ct_and_tag[ct_and_tag.len() - icv_len..];
            if ct.is_empty() || ct.len() % self.cipher.block_len() != 0 {
                return Err(IkeError::Crypto("ESP CBC ciphertext not block-aligned"));
            }
            let integ = self.cipher.integ_algorithm().expect("classic cipher has an integ algorithm");
            let mut mac_input = Vec::with_capacity(aad.len() + iv.len() + ct.len());
            mac_input.extend_from_slice(aad);
            mac_input.extend_from_slice(iv);
            mac_input.extend_from_slice(ct);
            let expected_icv = integ.compute(&self.integ_key, &mac_input);
            if !ct_eq(&expected_icv, icv) {
                return Err(IkeError::BadIntegrity);
            }
            cbc_decrypt(self.cipher, &self.enc_key, iv, ct)?
        };

        // Trailer: [ … | padding(pad_len) | pad_len | next_header ].
        if plaintext.len() < 2 {
            return Err(IkeError::Crypto("ESP plaintext shorter than its trailer"));
        }
        let next_header = plaintext[plaintext.len() - 1];
        let pad_len = plaintext[plaintext.len() - 2] as usize;
        if plaintext.len() < 2 + pad_len {
            return Err(IkeError::Crypto("ESP pad length exceeds plaintext"));
        }
        // RFC 4303 §2.4: padding bytes are 1, 2, 3, … pad_len -- the same
        // pattern `seal` writes below. Catches corruption/tampering that
        // slipped past a forged-but-consistent trailer.
        let pad_start = plaintext.len() - 2 - pad_len;
        for (i, &b) in plaintext[pad_start..plaintext.len() - 2].iter().enumerate() {
            if b != (i + 1) as u8 {
                return Err(IkeError::Crypto("ESP padding bytes malformed"));
            }
        }
        let inner = plaintext[..pad_start].to_vec();
        self.replay_advance(seq);
        Ok((inner, next_header))
    }
}

/// Both ESP directions for one endpoint of a CHILD SA.
pub struct ChildSa {
    /// SA we encrypt outbound traffic on (stamped with the peer's SPI).
    pub outbound: EspSa,
    /// SA we decrypt inbound traffic on (our own SPI).
    pub inbound: EspSa,
}

impl ChildSa {
    /// Derive both ESP SAs from the IKE SA's `SK_d`, the two nonces, our role,
    /// and the two ESP SPIs (`local_spi` is the SPI we chose in our SA payload;
    /// `peer_spi` is the SPI the peer chose), under the fixed AES-256-GCM
    /// cipher every caller of this constructor still uses today. Prefer
    /// [`Self::derive_with_cipher`] for any other [`SkCipher`]. RFC 7296
    /// §2.17: `encr_i` is the initiator's outbound key, `encr_r` the
    /// responder's; a packet carries the SPI of the SA that *receives* it.
    pub fn derive(prf: crate::crypto::PrfAlgorithm, sk_d: &[u8], ni: &[u8], nr: &[u8], role: Role, local_spi: u32, peer_spi: u32) -> ChildSa {
        Self::derive_with_cipher(prf, SkCipher::Aes256Gcm, sk_d, ni, nr, role, local_spi, peer_spi)
    }

    /// Like [`Self::derive`], but under an arbitrary negotiated ESP `cipher`.
    #[allow(clippy::too_many_arguments)]
    pub fn derive_with_cipher(
        prf: crate::crypto::PrfAlgorithm,
        cipher: SkCipher,
        sk_d: &[u8],
        ni: &[u8],
        nr: &[u8],
        role: Role,
        local_spi: u32,
        peer_spi: u32,
    ) -> ChildSa {
        let integ_len = cipher.integ_algorithm().map(IntegAlgorithm::key_len).unwrap_or(0);
        let keys = derive_child_keys(prf, sk_d, ni, nr, cipher.key_len() + cipher.salt_len(), integ_len);
        Self::from_keys(cipher, keys, role, local_spi, peer_spi)
    }

    /// Like [`Self::derive`], but for a **PFS** CHILD SA rekey: folds the
    /// fresh `shared_secret` from the rekey's own KE exchange into the seed
    /// (see [`crate::crypto::derive_child_keys_pfs`]) instead of deriving
    /// straight from `Ni | Nr`.
    #[allow(clippy::too_many_arguments)]
    pub fn derive_pfs(
        prf: crate::crypto::PrfAlgorithm,
        shared_secret: &[u8],
        sk_d: &[u8],
        ni: &[u8],
        nr: &[u8],
        role: Role,
        local_spi: u32,
        peer_spi: u32,
    ) -> ChildSa {
        Self::derive_with_cipher_pfs(prf, SkCipher::Aes256Gcm, shared_secret, sk_d, ni, nr, role, local_spi, peer_spi)
    }

    /// Like [`Self::derive_with_cipher`], but for a **PFS** CHILD SA rekey --
    /// see [`Self::derive_pfs`].
    #[allow(clippy::too_many_arguments)]
    pub fn derive_with_cipher_pfs(
        prf: crate::crypto::PrfAlgorithm,
        cipher: SkCipher,
        shared_secret: &[u8],
        sk_d: &[u8],
        ni: &[u8],
        nr: &[u8],
        role: Role,
        local_spi: u32,
        peer_spi: u32,
    ) -> ChildSa {
        let integ_len = cipher.integ_algorithm().map(IntegAlgorithm::key_len).unwrap_or(0);
        let keys = derive_child_keys_pfs(prf, sk_d, shared_secret, ni, nr, cipher.key_len() + cipher.salt_len(), integ_len);
        Self::from_keys(cipher, keys, role, local_spi, peer_spi)
    }

    fn from_keys(cipher: SkCipher, keys: ChildKeys, role: Role, local_spi: u32, peer_spi: u32) -> ChildSa {
        let esp = |spi: u32, enc: &[u8], integ: &[u8]| {
            EspSa::new_with_cipher(spi, cipher, enc, integ).expect("derive_child_keys produced correctly-sized material")
        };
        match role {
            Role::Initiator => ChildSa {
                outbound: esp(peer_spi, &keys.encr_i, &keys.integ_i),
                inbound: esp(local_spi, &keys.encr_r, &keys.integ_r),
            },
            Role::Responder => ChildSa {
                outbound: esp(peer_spi, &keys.encr_r, &keys.integ_r),
                inbound: esp(local_spi, &keys.encr_i, &keys.integ_i),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip() {
        let km = [0x42u8; 36];
        let mut tx = EspSa::new(0xCAFE_BABE, &km).unwrap();
        let mut rx = EspSa::new(0xCAFE_BABE, &km).unwrap();

        let inner = b"a pretend inner IP packet with some length".to_vec();
        let packet = tx.seal(&inner, next_header::IPV4).unwrap();
        assert_eq!(&packet[0..4], &0xCAFE_BABEu32.to_be_bytes()); // SPI on the wire

        let (out, nh) = rx.open(&packet).unwrap();
        assert_eq!(out, inner);
        assert_eq!(nh, next_header::IPV4);
    }

    #[test]
    fn various_lengths_roundtrip_with_correct_padding() {
        let km = [9u8; 36];
        for len in 0..40 {
            let mut tx = EspSa::new(1, &km).unwrap();
            let mut rx = EspSa::new(1, &km).unwrap();
            let inner: Vec<u8> = (0..len as u8).collect();
            let packet = tx.seal(&inner, next_header::IPV6).unwrap();
            // ciphertext (after SPI|Seq|IV, before the 16-byte tag) is 4-aligned.
            let ct_len = packet.len() - ESP_HEADER_LEN - IV_LEN - 16;
            assert_eq!(ct_len % 4, 0, "len {len}");
            let (out, nh) = rx.open(&packet).unwrap();
            assert_eq!(out, inner);
            assert_eq!(nh, next_header::IPV6);
        }
    }

    #[test]
    fn sequence_increments_and_nonces_differ() {
        let mut tx = EspSa::new(1, &[1u8; 36]).unwrap();
        let p1 = tx.seal(b"x", 4).unwrap();
        let p2 = tx.seal(b"x", 4).unwrap();
        assert_ne!(&p1[4..8], &p2[4..8]); // sequence number advanced
        assert_ne!(p1, p2); // distinct ciphertext (distinct nonce)
    }

    #[test]
    fn wrong_spi_is_rejected() {
        let mut tx = EspSa::new(10, &[2u8; 36]).unwrap();
        let mut rx = EspSa::new(11, &[2u8; 36]).unwrap();
        let packet = tx.seal(b"hello", 4).unwrap();
        assert!(matches!(rx.open(&packet), Err(IkeError::Crypto(_))));
    }

    #[test]
    fn tampering_and_wrong_key_are_rejected() {
        let mut tx = EspSa::new(5, &[3u8; 36]).unwrap();
        let mut rx = EspSa::new(5, &[3u8; 36]).unwrap();
        let mut packet = tx.seal(b"hello world", 4).unwrap();
        let last = packet.len() - 1;
        packet[last] ^= 1;
        assert_eq!(rx.open(&packet).unwrap_err(), IkeError::BadIntegrity);

        let mut tx2 = EspSa::new(5, &[7u8; 36]).unwrap();
        let mut rx2 = EspSa::new(5, &[8u8; 36]).unwrap();
        let good = tx2.seal(b"y", 4).unwrap();
        assert_eq!(rx2.open(&good).unwrap_err(), IkeError::BadIntegrity);
    }

    #[test]
    fn malformed_padding_bytes_are_rejected() {
        // Forge a packet whose AEAD tag is valid (so it passes authentication)
        // but whose padding trailer doesn't follow the RFC 4303 §2.4
        // 1,2,3,... pattern -- exercises the new padding check independently
        // of the (already-covered) tag-tamper path.
        let tx = EspSa::new(1, &[4u8; 36]).unwrap();
        let mut rx = EspSa::new(1, &[4u8; 36]).unwrap();

        let inner = b"hello".to_vec();
        let pad_len = 3u8;
        let mut plaintext = inner.clone();
        plaintext.extend_from_slice(&[0xFF, 0xFF, 0xFF]); // wrong: should be 1,2,3
        plaintext.push(pad_len);
        plaintext.push(next_header::IPV4);

        let seq: u32 = 1;
        let iv_bytes = [0x11u8; IV_LEN];
        let mut aad = [0u8; ESP_HEADER_LEN];
        aad[..4].copy_from_slice(&tx.spi.to_be_bytes());
        aad[4..].copy_from_slice(&seq.to_be_bytes());

        let ct_and_tag = aead_seal_dispatch(tx.cipher, &tx.enc_key, &tx.nonce(&iv_bytes), &aad, &plaintext).unwrap();

        let mut packet = Vec::new();
        packet.extend_from_slice(&aad);
        packet.extend_from_slice(&iv_bytes);
        packet.extend_from_slice(&ct_and_tag);

        assert_eq!(rx.open(&packet).unwrap_err(), IkeError::Crypto("ESP padding bytes malformed"));
    }

    #[test]
    fn replayed_packet_is_rejected_but_out_of_order_within_window_is_accepted() {
        let km = [7u8; 36];
        let mut tx = EspSa::new(1, &km).unwrap();
        let mut rx = EspSa::new(1, &km).unwrap();

        let p1 = tx.seal(b"one", next_header::IPV4).unwrap();
        let p2 = tx.seal(b"two", next_header::IPV4).unwrap();
        let p3 = tx.seal(b"three", next_header::IPV4).unwrap();

        // In-order delivery of the first packet succeeds.
        assert_eq!(rx.open(&p1).unwrap().0, b"one");
        // Replaying the same packet must be rejected.
        assert_eq!(rx.open(&p1).unwrap_err(), IkeError::Crypto("ESP replay detected"));

        // Out-of-order but not-yet-seen packets within the window are accepted...
        assert_eq!(rx.open(&p3).unwrap().0, b"three");
        assert_eq!(rx.open(&p2).unwrap().0, b"two");
        // ...but replaying either of them afterward is rejected.
        assert_eq!(rx.open(&p2).unwrap_err(), IkeError::Crypto("ESP replay detected"));
        assert_eq!(rx.open(&p3).unwrap_err(), IkeError::Crypto("ESP replay detected"));
    }

    #[test]
    fn packet_older_than_the_replay_window_is_rejected() {
        let km = [8u8; 36];
        let mut tx = EspSa::new(1, &km).unwrap();
        let mut rx = EspSa::new(1, &km).unwrap();

        let old = tx.seal(b"old", next_header::IPV4).unwrap();
        for _ in 0..70 {
            let _ = tx.seal(b"filler", next_header::IPV4).unwrap();
        }
        let fresh = tx.seal(b"fresh", next_header::IPV4).unwrap();
        assert_eq!(rx.open(&fresh).unwrap().0, b"fresh");
        assert_eq!(rx.open(&old).unwrap_err(), IkeError::Crypto("ESP replay detected"));
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

    #[test]
    fn every_aead_cipher_roundtrips_various_lengths() {
        for cipher in aead_ciphers() {
            let enc = vec![0x24u8; cipher.key_len() + cipher.salt_len()];
            for len in [0usize, 1, 15, 16, 17, 40] {
                let mut tx = EspSa::new_with_cipher(1, cipher, &enc, &[]).unwrap();
                let mut rx = EspSa::new_with_cipher(1, cipher, &enc, &[]).unwrap();
                let inner: Vec<u8> = (0..len as u8).collect();
                let packet = tx.seal(&inner, next_header::IPV4).unwrap();
                let (out, nh) = rx.open(&packet).unwrap();
                assert_eq!(out, inner, "{cipher:?} len={len}");
                assert_eq!(nh, next_header::IPV4, "{cipher:?} len={len}");
            }
        }
    }

    #[test]
    fn every_cbc_cipher_roundtrips_various_lengths() {
        for cipher in cbc_ciphers() {
            let integ = cipher.integ_algorithm().unwrap();
            let enc = vec![0x31u8; cipher.key_len()];
            let ik = vec![0x62u8; integ.key_len()];
            for len in [0usize, 1, 15, 16, 17, 40] {
                let mut tx = EspSa::new_with_cipher(1, cipher, &enc, &ik).unwrap();
                let mut rx = EspSa::new_with_cipher(1, cipher, &enc, &ik).unwrap();
                let inner: Vec<u8> = (0..len as u8).collect();
                let packet = tx.seal(&inner, next_header::IPV6).unwrap();
                let (out, nh) = rx.open(&packet).unwrap();
                assert_eq!(out, inner, "{cipher:?} len={len}");
                assert_eq!(nh, next_header::IPV6, "{cipher:?} len={len}");
            }
        }
    }

    #[test]
    fn cbc_iv_differs_per_packet_and_ciphertext_is_block_aligned() {
        for cipher in cbc_ciphers() {
            let integ = cipher.integ_algorithm().unwrap();
            let enc = vec![0x11u8; cipher.key_len()];
            let ik = vec![0x22u8; integ.key_len()];
            let mut tx = EspSa::new_with_cipher(7, cipher, &enc, &ik).unwrap();
            let p1 = tx.seal(b"same plaintext", 4).unwrap();
            let p2 = tx.seal(b"same plaintext", 4).unwrap();
            let block = cipher.block_len();
            let iv1 = &p1[ESP_HEADER_LEN..ESP_HEADER_LEN + block];
            let iv2 = &p2[ESP_HEADER_LEN..ESP_HEADER_LEN + block];
            assert_ne!(iv1, iv2, "{cipher:?}");
            assert_ne!(p1, p2, "{cipher:?}");
        }
    }

    #[test]
    fn cbc_tampering_and_wrong_integ_key_are_rejected() {
        for cipher in cbc_ciphers() {
            let integ = cipher.integ_algorithm().unwrap();
            let enc = vec![0x44u8; cipher.key_len()];
            let ik = vec![0x55u8; integ.key_len()];
            let mut tx = EspSa::new_with_cipher(5, cipher, &enc, &ik).unwrap();
            let mut rx = EspSa::new_with_cipher(5, cipher, &enc, &ik).unwrap();
            let mut packet = tx.seal(b"hello world", 4).unwrap();
            let last = packet.len() - 1;
            packet[last] ^= 1;
            assert_eq!(rx.open(&packet).unwrap_err(), IkeError::BadIntegrity, "{cipher:?}");

            let mut bad_ik = ik.clone();
            bad_ik[0] ^= 0xff;
            let mut tx2 = EspSa::new_with_cipher(5, cipher, &enc, &ik).unwrap();
            let mut rx2 = EspSa::new_with_cipher(5, cipher, &enc, &bad_ik).unwrap();
            let good = tx2.seal(b"y", 4).unwrap();
            assert_eq!(rx2.open(&good).unwrap_err(), IkeError::BadIntegrity, "{cipher:?}");
        }
    }

    #[test]
    fn derive_with_cipher_matches_across_the_matrix() {
        use crate::crypto::PrfAlgorithm;
        for cipher in aead_ciphers().into_iter().chain(cbc_ciphers()) {
            let sk_d = [0x77u8; 32];
            let ni = [0x11u8; 32];
            let nr = [0x22u8; 32];
            let mut init = ChildSa::derive_with_cipher(PrfAlgorithm::Sha256, cipher, &sk_d, &ni, &nr, Role::Initiator, 100, 200);
            let mut resp = ChildSa::derive_with_cipher(PrfAlgorithm::Sha256, cipher, &sk_d, &ni, &nr, Role::Responder, 200, 100);

            let pkt = init.outbound.seal(b"init->resp", next_header::IPV4).unwrap();
            assert_eq!(resp.inbound.open(&pkt).unwrap().0, b"init->resp", "{cipher:?}");
            let pkt2 = resp.outbound.seal(b"resp->init", next_header::IPV4).unwrap();
            assert_eq!(init.inbound.open(&pkt2).unwrap().0, b"resp->init", "{cipher:?}");
        }
    }
}
