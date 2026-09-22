//! RFC 7427 "Signature Authentication in IKEv2" (Auth Method 14) plus the X.509
//! plumbing native iOS/Android clients use to authenticate the ryke **server**
//! by certificate. (The client still authenticates via EAP-MSCHAPv2.)
//!
//! The method-14 AUTH payload *Data* (the bytes after the 4-byte method+RESERVED
//! header handled by [`crate::ikev2::payload::Authentication`]) is:
//!
//! ```text
//! [1 octet ASN.1 length L] [ L octets: DER AlgorithmIdentifier ] [ signature value ]
//! ```
//!
//! The signature is computed over the exact RFC 7296 §2.15 octets
//! ([`crate::ikev2::auth::responder_signed_octets`] etc.) — method 14 only swaps the
//! final PSK `prf` for a real public-key signature over those same octets.
//!
//! Supported schemes: `sha256WithRSAEncryption` (RSA PKCS#1 v1.5, sign+verify),
//! `ecdsa-with-SHA256` on P-256 (sign+verify, DER `SEQUENCE{r,s}` on the wire),
//! and RSASSA-PSS/SHA-256 (verify only — we accept it from a peer but emit the
//! two widely-interoperable schemes).

use crate::error::IkeError;
use sha2::{Digest, Sha256};

/// DER-encoded `AlgorithmIdentifier`s (RFC 7427 §3 / RFC 5758 / RFC 4055).
pub mod sig_alg {
    /// `sha256WithRSAEncryption`, OID 1.2.840.113549.1.1.11 (SEQUENCE{OID, NULL}).
    pub const RSA_SHA256: &[u8] = &[
        0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00,
    ];
    /// `ecdsa-with-SHA256`, OID 1.2.840.10045.4.3.2 (no parameters, per RFC 5758).
    pub const ECDSA_P256_SHA256: &[u8] =
        &[0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
    /// RSASSA-PSS / SHA-256 / MGF1-SHA256 / salt 32, OID 1.2.840.113549.1.1.10.
    /// Always the explicit 65-byte form — the short "default parameters" form
    /// means SHA-1 and would fail SHA-256 verification.
    pub const RSA_PSS_SHA256: &[u8] = &[
        0x30, 0x41, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a, // rsassaPss
        0x30, 0x34, // parameters SEQUENCE
        0xa0, 0x0f, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        0x05, 0x00, // [0] hashAlgorithm sha256 + NULL
        0xa1, 0x1c, 0x30, 0x1a, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
        0x08, // [1] maskGenAlgorithm mgf1
        0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
        0x00, //     with sha256 + NULL
        0xa2, 0x03, 0x02, 0x01, 0x20, // [2] saltLength 32
    ];
}

// X.509 / PKIX algorithm OIDs (dotted form), matched against certificate fields.
const OID_RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";
const OID_EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
const OID_SHA256_WITH_RSA: &str = "1.2.840.113549.1.1.11";
const OID_ECDSA_WITH_SHA256: &str = "1.2.840.10045.4.3.2";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Scheme {
    RsaPkcs1Sha256,
    RsaPssSha256,
    EcdsaP256Sha256,
}

fn scheme_of(alg: &[u8]) -> Option<Scheme> {
    if alg == sig_alg::RSA_SHA256 {
        Some(Scheme::RsaPkcs1Sha256)
    } else if alg == sig_alg::RSA_PSS_SHA256 {
        Some(Scheme::RsaPssSha256)
    } else if alg == sig_alg::ECDSA_P256_SHA256 {
        Some(Scheme::EcdsaP256Sha256)
    } else {
        None
    }
}

/// Wrap a DER AlgorithmIdentifier + raw signature into method-14 AUTH Data.
fn wrap_auth_data(alg: &[u8], sig: &[u8]) -> Vec<u8> {
    debug_assert!(alg.len() < 256, "AlgorithmIdentifier must fit a 1-octet length");
    let mut data = Vec::with_capacity(1 + alg.len() + sig.len());
    data.push(alg.len() as u8);
    data.extend_from_slice(alg);
    data.extend_from_slice(sig);
    data
}

/// Split method-14 AUTH Data into its `(DER AlgorithmIdentifier, signature)`.
pub fn parse_auth_data(data: &[u8]) -> Result<(&[u8], &[u8]), IkeError> {
    let l = *data.first().ok_or(IkeError::Truncated { need: 1, have: 0 })? as usize;
    let end = 1 + l;
    if data.len() < end {
        return Err(IkeError::Truncated { need: end, have: data.len() });
    }
    Ok((&data[1..end], &data[end..]))
}

/// A server private key that produces RFC 7427 Digital Signatures over the
/// `IKE_AUTH` signed octets.
pub enum SigningKey {
    /// RSA, PKCS#1 v1.5 padding, SHA-256 (`sha256WithRSAEncryption`). Boxed
    /// because an `RsaPrivateKey` dwarfs the other variant.
    RsaSha256(Box<rsa::RsaPrivateKey>),
    /// ECDSA on P-256 with SHA-256 (deterministic, RFC 6979).
    EcdsaP256(p256::ecdsa::SigningKey),
}

impl SigningKey {
    /// Load an ECDSA P-256 signing key from a PKCS#8 DER document — the form a
    /// server certificate's private key is generated in (`openssl pkcs8 …`).
    pub fn ecdsa_p256_from_pkcs8_der(der: &[u8]) -> Result<Self, IkeError> {
        use p256::pkcs8::DecodePrivateKey;
        let key = p256::ecdsa::SigningKey::from_pkcs8_der(der)
            .map_err(|_| IkeError::Crypto("bad EC PKCS#8 DER private key"))?;
        Ok(SigningKey::EcdsaP256(key))
    }

    /// Load an RSA signing key from a PKCS#8 DER document
    /// (`-----BEGIN PRIVATE KEY-----`, e.g. `openssl pkcs8 …` output).
    pub fn rsa_from_pkcs8_der(der: &[u8]) -> Result<Self, IkeError> {
        use rsa::pkcs8::DecodePrivateKey;
        let key = rsa::RsaPrivateKey::from_pkcs8_der(der)
            .map_err(|_| IkeError::Crypto("bad RSA PKCS#8 DER private key"))?;
        Ok(SigningKey::RsaSha256(Box::new(key)))
    }

    /// Load an RSA signing key from a PKCS#1 DER document
    /// (`-----BEGIN RSA PRIVATE KEY-----`) — the older, PKCS#8-less form some
    /// tooling still emits (e.g. `openssl genrsa` without `pkcs8` wrapping).
    pub fn rsa_from_pkcs1_der(der: &[u8]) -> Result<Self, IkeError> {
        use rsa::pkcs1::DecodeRsaPrivateKey;
        let key = rsa::RsaPrivateKey::from_pkcs1_der(der)
            .map_err(|_| IkeError::Crypto("bad RSA PKCS#1 DER private key"))?;
        Ok(SigningKey::RsaSha256(Box::new(key)))
    }

    /// The DER `AlgorithmIdentifier` this key advertises in the AUTH payload.
    pub fn algorithm_id(&self) -> &'static [u8] {
        match self {
            SigningKey::RsaSha256(_) => sig_alg::RSA_SHA256,
            SigningKey::EcdsaP256(_) => sig_alg::ECDSA_P256_SHA256,
        }
    }

    /// Sign the §2.15 `signed_octets`, returning the full method-14 AUTH Data
    /// (`[len][DER alg][signature]`).
    pub fn sign_auth_data(&self, signed_octets: &[u8]) -> Result<Vec<u8>, IkeError> {
        let digest = Sha256::digest(signed_octets);
        let sig = match self {
            SigningKey::RsaSha256(key) => key
                .sign(rsa::Pkcs1v15Sign::new::<Sha256>(), &digest)
                .map_err(|_| IkeError::Crypto("RSA signing failed"))?,
            SigningKey::EcdsaP256(key) => {
                use p256::ecdsa::signature::hazmat::PrehashSigner;
                let sig: p256::ecdsa::Signature = key
                    .sign_prehash(&digest)
                    .map_err(|_| IkeError::Crypto("ECDSA signing failed"))?;
                // RFC 7427 puts the ASN.1 DER SEQUENCE{r,s} on the wire, not r||s.
                sig.to_der().as_bytes().to_vec()
            }
        };
        Ok(wrap_auth_data(self.algorithm_id(), &sig))
    }

    /// Sign as the classic IKEv2 method-9 AUTH (ECDSA-256, RFC 4754): the raw
    /// `r || s` (64 bytes for P-256) over `SHA-256(octets)`, with no RFC 7427
    /// algorithm wrapper. Used when the peer does not negotiate Digital
    /// Signature (a native EAP client that sends no SIGNATURE_HASH_ALGORITHMS).
    pub fn sign_ecdsa_p256_raw(&self, signed_octets: &[u8]) -> Result<Vec<u8>, IkeError> {
        match self {
            SigningKey::EcdsaP256(key) => {
                use p256::ecdsa::signature::hazmat::PrehashSigner;
                let digest = Sha256::digest(signed_octets);
                let sig: p256::ecdsa::Signature = key
                    .sign_prehash(&digest)
                    .map_err(|_| IkeError::Crypto("ECDSA signing failed"))?;
                Ok(sig.to_bytes().to_vec())
            }
            SigningKey::RsaSha256(_) => Err(IkeError::Crypto("method 9 needs an ECDSA P-256 key")),
        }
    }

    /// Sign `data` directly with PKCS#1 v1.5 padding and no ASN.1
    /// `DigestInfo` prefix (`rsa::Pkcs1v15Sign::new_unprefixed`) — the classic
    /// IKEv1 SIG payload convention (RFC 2409 §5.1): `HASH_I`/`HASH_R` (an
    /// HMAC/PRF output) is signed as-is, unlike IKEv2's methods 1/14 which
    /// re-hash the signed octets with SHA-256/SHA-1 first (see
    /// `verify_classic_rsa_auth_data` below). Confirmed against isakmpd's
    /// `rsa_sig_encode_hash`, which calls OpenSSL's
    /// `RSA_private_encrypt(..., RSA_PKCS1_PADDING)` directly over the raw
    /// hash bytes.
    pub fn sign_classic_rsa_raw(&self, data: &[u8]) -> Result<Vec<u8>, IkeError> {
        match self {
            SigningKey::RsaSha256(key) => key
                .sign(rsa::Pkcs1v15Sign::new_unprefixed(), data)
                .map_err(|_| IkeError::Crypto("RSA signing failed")),
            SigningKey::EcdsaP256(_) => Err(IkeError::Crypto("IKEv1 SIG payload needs an RSA certificate key")),
        }
    }
}

/// A public key that verifies RFC 7427 Digital Signatures.
pub enum VerifyingKey {
    Rsa(rsa::RsaPublicKey),
    EcdsaP256(p256::ecdsa::VerifyingKey),
}

impl VerifyingKey {
    /// Extract the public key from a DER-encoded X.509 leaf certificate.
    pub fn from_cert_der(cert_der: &[u8]) -> Result<VerifyingKey, IkeError> {
        use der::{Decode, Encode};
        let cert = x509_cert::Certificate::from_der(cert_der)
            .map_err(|_| IkeError::Crypto("malformed certificate DER"))?;
        let spki = &cert.tbs_certificate.subject_public_key_info;
        let spki_der = spki.to_der().map_err(|_| IkeError::Crypto("malformed SPKI"))?;
        Self::from_spki_der(&spki_der, &spki.algorithm.oid.to_string())
    }

    fn from_spki_der(spki_der: &[u8], alg_oid: &str) -> Result<VerifyingKey, IkeError> {
        match alg_oid {
            OID_RSA_ENCRYPTION => {
                use rsa::pkcs8::DecodePublicKey;
                Ok(VerifyingKey::Rsa(
                    rsa::RsaPublicKey::from_public_key_der(spki_der)
                        .map_err(|_| IkeError::Crypto("malformed RSA public key"))?,
                ))
            }
            OID_EC_PUBLIC_KEY => {
                use p256::pkcs8::DecodePublicKey;
                // from_public_key_der rejects any curve other than P-256.
                Ok(VerifyingKey::EcdsaP256(
                    p256::ecdsa::VerifyingKey::from_public_key_der(spki_der)
                        .map_err(|_| IkeError::Crypto("unsupported EC curve (need P-256)"))?,
                ))
            }
            _ => Err(IkeError::Crypto("unsupported certificate key algorithm")),
        }
    }

    /// Verify a classic IKEv1 SIG payload: `sig` is a raw PKCS#1 v1.5
    /// signature over `data` directly, no `DigestInfo` prefix — the
    /// counterpart to `SigningKey::sign_classic_rsa_raw`. `data` is normally
    /// an already-computed `HASH_I`/`HASH_R` (see `crypto1::hash_i`/`hash_r`),
    /// not a message to be hashed again.
    pub fn verify_classic_rsa_raw(&self, sig: &[u8], data: &[u8]) -> Result<(), IkeError> {
        let VerifyingKey::Rsa(pk) = self else {
            return Err(IkeError::Crypto("IKEv1 SIG payload needs an RSA certificate key"));
        };
        pk.verify(rsa::Pkcs1v15Sign::new_unprefixed(), data, sig)
            .map_err(|_| IkeError::AuthFailed)
    }

    /// Verify classic RFC 7296 §3.8 method-1 (RSA Digital Signature) AUTH
    /// Data: a plain PKCS#1 v1.5 signature over the §2.15 `signed_octets`
    /// with a `DigestInfo`-prefixed digest, unlike method 14's
    /// algorithm-tagged encoding. Tries SHA-256 first, then falls back to
    /// SHA-1 (the historical RFC 7296 default) since peers vary on which
    /// digest they actually used.
    pub fn verify_classic_rsa_auth_data(&self, sig: &[u8], signed_octets: &[u8]) -> Result<(), IkeError> {
        let VerifyingKey::Rsa(pk) = self else {
            return Err(IkeError::Crypto("method 1 (RSA Digital Signature) needs an RSA certificate key"));
        };
        if pk.verify(rsa::Pkcs1v15Sign::new::<Sha256>(), &Sha256::digest(signed_octets), sig).is_ok() {
            return Ok(());
        }
        use sha1::Sha1;
        if pk.verify(rsa::Pkcs1v15Sign::new::<Sha1>(), &Sha1::digest(signed_octets), sig).is_ok() {
            return Ok(());
        }
        Err(IkeError::AuthFailed)
    }

    /// Verify method-14 AUTH Data against the §2.15 `signed_octets`.
    pub fn verify_auth_data(&self, auth_data: &[u8], signed_octets: &[u8]) -> Result<(), IkeError> {
        let (alg, sig) = parse_auth_data(auth_data)?;
        let scheme = scheme_of(alg).ok_or(IkeError::Crypto("unsupported signature algorithm"))?;
        let digest = Sha256::digest(signed_octets);
        match (self, scheme) {
            (VerifyingKey::Rsa(pk), Scheme::RsaPkcs1Sha256) => pk
                .verify(rsa::Pkcs1v15Sign::new::<Sha256>(), &digest, sig)
                .map_err(|_| IkeError::AuthFailed),
            (VerifyingKey::Rsa(pk), Scheme::RsaPssSha256) => pk
                .verify(rsa::Pss::new::<Sha256>(), &digest, sig)
                .map_err(|_| IkeError::AuthFailed),
            (VerifyingKey::EcdsaP256(vk), Scheme::EcdsaP256Sha256) => {
                use p256::ecdsa::signature::hazmat::PrehashVerifier;
                let sig =
                    p256::ecdsa::Signature::from_der(sig).map_err(|_| IkeError::AuthFailed)?;
                vk.verify_prehash(&digest, &sig).map_err(|_| IkeError::AuthFailed)
            }
            _ => Err(IkeError::Crypto("signature algorithm does not match certificate key")),
        }
    }
}

/// Verify that `leaf_der`'s `TBSCertificate` was signed by the key in
/// `issuer_der` — one hop of an X.509 chain.
///
/// This checks only the cryptographic signature. It deliberately does **not**
/// validate notBefore/notAfter, subject/issuer name chaining, BasicConstraints,
/// key usage, or revocation; a consumer needing full RFC 5280 path validation
/// must layer that on top (see the crate docs).
pub fn verify_cert_signed_by(leaf_der: &[u8], issuer_der: &[u8]) -> Result<(), IkeError> {
    use der::{Decode, Encode};
    let leaf = x509_cert::Certificate::from_der(leaf_der)
        .map_err(|_| IkeError::Crypto("malformed leaf certificate"))?;
    let issuer_key = VerifyingKey::from_cert_der(issuer_der)?;
    let tbs = leaf.tbs_certificate.to_der().map_err(|_| IkeError::Crypto("malformed TBS"))?;
    let sig = leaf.signature.as_bytes().ok_or(IkeError::Crypto("unaligned cert signature"))?;
    let alg_oid = leaf.signature_algorithm.oid.to_string();
    let digest = Sha256::digest(&tbs);
    match (&issuer_key, alg_oid.as_str()) {
        (VerifyingKey::Rsa(pk), OID_SHA256_WITH_RSA) => pk
            .verify(rsa::Pkcs1v15Sign::new::<Sha256>(), &digest, sig)
            .map_err(|_| IkeError::AuthFailed),
        (VerifyingKey::EcdsaP256(vk), OID_ECDSA_WITH_SHA256) => {
            use p256::ecdsa::signature::hazmat::PrehashVerifier;
            let s = p256::ecdsa::Signature::from_der(sig).map_err(|_| IkeError::AuthFailed)?;
            vk.verify_prehash(&digest, &s).map_err(|_| IkeError::AuthFailed)
        }
        _ => Err(IkeError::Crypto("unsupported certificate signature algorithm")),
    }
}

/// A certificate's `SubjectAltName` dNSName entries, verbatim (no case
/// normalization). Shared by [`cert_has_dns_name`] and `validate_chain`'s
/// name-constraint enforcement.
fn cert_dns_names(cert_der: &[u8]) -> Result<Vec<String>, IkeError> {
    use der::Decode;
    use x509_cert::ext::pkix::{name::GeneralName, SubjectAltName};
    let cert = x509_cert::Certificate::from_der(cert_der)
        .map_err(|_| IkeError::Crypto("malformed certificate DER"))?;
    let Some(exts) = &cert.tbs_certificate.extensions else { return Ok(Vec::new()) };
    for ext in exts.iter() {
        // id-ce-subjectAltName (2.5.29.17).
        if ext.extn_id.to_string() != "2.5.29.17" {
            continue;
        }
        let san = SubjectAltName::from_der(ext.extn_value.as_bytes())
            .map_err(|_| IkeError::Crypto("malformed SubjectAltName"))?;
        return Ok(san
            .0
            .iter()
            .filter_map(|gn| match gn {
                GeneralName::DnsName(dns) => Some(dns.as_str().to_string()),
                _ => None,
            })
            .collect());
    }
    Ok(Vec::new())
}

/// Whether the certificate's `SubjectAltName` contains `name` as a dNSName
/// (exact, ASCII-case-insensitive; wildcards are not expanded). Modern
/// iOS/Android bind the server identity this way — a valid cert for one host
/// must not authenticate another, so callers doing cert auth must check this.
pub fn cert_has_dns_name(cert_der: &[u8], name: &str) -> Result<bool, IkeError> {
    Ok(cert_dns_names(cert_der)?.iter().any(|dns| dns.eq_ignore_ascii_case(name)))
}

/// A certificate's `(notBefore, notAfter)` as Unix seconds.
pub fn cert_validity(cert_der: &[u8]) -> Result<(u64, u64), IkeError> {
    use der::Decode;
    let cert = x509_cert::Certificate::from_der(cert_der)
        .map_err(|_| IkeError::Crypto("malformed certificate DER"))?;
    let v = &cert.tbs_certificate.validity;
    Ok((v.not_before.to_unix_duration().as_secs(), v.not_after.to_unix_duration().as_secs()))
}

/// A certificate's `BasicConstraints`, if present.
fn basic_constraints(cert_der: &[u8]) -> Result<Option<x509_cert::ext::pkix::BasicConstraints>, IkeError> {
    use der::Decode;
    use x509_cert::ext::pkix::BasicConstraints;
    let cert = x509_cert::Certificate::from_der(cert_der)
        .map_err(|_| IkeError::Crypto("malformed certificate DER"))?;
    let Some(exts) = &cert.tbs_certificate.extensions else { return Ok(None) };
    for ext in exts.iter() {
        if ext.extn_id.to_string() == "2.5.29.19" {
            let bc = BasicConstraints::from_der(ext.extn_value.as_bytes())
                .map_err(|_| IkeError::Crypto("malformed BasicConstraints"))?;
            return Ok(Some(bc));
        }
    }
    Ok(None)
}

/// Whether a certificate asserts `BasicConstraints` with `CA:TRUE`.
pub fn cert_is_ca(cert_der: &[u8]) -> Result<bool, IkeError> {
    Ok(basic_constraints(cert_der)?.is_some_and(|bc| bc.ca))
}

/// A certificate's `KeyUsage`, if present.
fn key_usage(cert_der: &[u8]) -> Result<Option<x509_cert::ext::pkix::KeyUsage>, IkeError> {
    use der::Decode;
    use x509_cert::ext::pkix::KeyUsage;
    let cert = x509_cert::Certificate::from_der(cert_der)
        .map_err(|_| IkeError::Crypto("malformed certificate DER"))?;
    let Some(exts) = &cert.tbs_certificate.extensions else { return Ok(None) };
    for ext in exts.iter() {
        if ext.extn_id.to_string() == "2.5.29.15" {
            let ku = KeyUsage::from_der(ext.extn_value.as_bytes())
                .map_err(|_| IkeError::Crypto("malformed KeyUsage"))?;
            return Ok(Some(ku));
        }
    }
    Ok(None)
}

/// A certificate's `NameConstraints`, if present.
fn name_constraints(cert_der: &[u8]) -> Result<Option<x509_cert::ext::pkix::NameConstraints>, IkeError> {
    use der::Decode;
    use x509_cert::ext::pkix::NameConstraints;
    let cert = x509_cert::Certificate::from_der(cert_der)
        .map_err(|_| IkeError::Crypto("malformed certificate DER"))?;
    let Some(exts) = &cert.tbs_certificate.extensions else { return Ok(None) };
    for ext in exts.iter() {
        if ext.extn_id.to_string() == "2.5.29.30" {
            let nc = NameConstraints::from_der(ext.extn_value.as_bytes())
                .map_err(|_| IkeError::Crypto("malformed NameConstraints"))?;
            return Ok(Some(nc));
        }
    }
    Ok(None)
}

/// RFC 5280 §4.2.1.9: whether a CA whose `BasicConstraints.pathLenConstraint`
/// is `path_len` may still have `cas_below` non-self-issued intermediate CA
/// certificates follow it before the end-entity certificate. `None` (the
/// extension omitted the field, meaning "unconstrained") always allows.
fn path_len_ok(path_len: Option<u8>, cas_below: u8) -> bool {
    match path_len {
        Some(max) => cas_below <= max,
        None => true,
    }
}

/// RFC 5280 §4.2.1.3: whether a `KeyUsage` (if present) authorizes its
/// holder to sign other certificates. A cert asserting `CA:TRUE` but whose
/// KeyUsage explicitly omits `keyCertSign` is not a valid issuer despite the
/// BasicConstraints flag -- the case the audit's "KeyUsage, especially la
/// autorización de una CA para firmar certificados" specifically calls out.
/// A missing KeyUsage extension is permissive (many real-world CAs omit it).
fn key_cert_sign_ok(ku: Option<&x509_cert::ext::pkix::KeyUsage>) -> bool {
    ku.is_none_or(|ku| ku.key_cert_sign())
}

/// RFC 5280 §4.2.1.10 dNSName matching: `name` is within the domain `base`
/// expresses (exact match, or a subdomain of it), ASCII-case-insensitive.
fn dns_name_within_base(name: &str, base: &str) -> bool {
    if name.eq_ignore_ascii_case(base) {
        return true;
    }
    match name.len().checked_sub(base.len()) {
        Some(prefix_len) if prefix_len > 0 => {
            name[prefix_len - 1..prefix_len] == *"."
                && name[prefix_len..].eq_ignore_ascii_case(base)
        }
        _ => false,
    }
}

/// RFC 5280 §4.2.1.10: whether `nc` permits every name in `leaf_dns`. Only
/// dNSName-typed subtrees are enforced -- a constraint list containing only
/// other name forms (rfc822Name, directoryName, ...) doesn't restrict
/// dNSName and is treated as no restriction, matching the RFC's per-name-type
/// scoping. This only checks the leaf's own SAN dNSNames, not intermediate
/// certificates' names -- the leaf's dNSName is the only identity this
/// crate's callers ever bind to (see `expected_dns` in `verify_cert_auth`).
fn name_constraints_allow(nc: &x509_cert::ext::pkix::NameConstraints, leaf_dns: &[String]) -> bool {
    use x509_cert::ext::pkix::{constraints::name::GeneralSubtree, name::GeneralName};
    fn dns_bases(subtrees: &Option<Vec<GeneralSubtree>>) -> Vec<&str> {
        subtrees
            .iter()
            .flatten()
            .filter_map(|st| match &st.base {
                GeneralName::DnsName(s) => Some(s.as_str()),
                _ => None,
            })
            .collect()
    }
    let excluded = dns_bases(&nc.excluded_subtrees);
    if leaf_dns.iter().any(|n| excluded.iter().any(|b| dns_name_within_base(n, b))) {
        return false;
    }
    let permitted = dns_bases(&nc.permitted_subtrees);
    if !permitted.is_empty() && !leaf_dns.iter().all(|n| permitted.iter().any(|b| dns_name_within_base(n, b))) {
        return false;
    }
    true
}

/// Whether `cert_der` is authorized to have issued whatever comes below it
/// in the path: its `pathLenConstraint` (if any) isn't exceeded, its
/// `KeyUsage` (if any) permits signing certificates, and its
/// `NameConstraints` (if any) don't exclude / fail to permit the leaf's own
/// SAN dNSNames. Applied uniformly to accepted intermediates and to the
/// trust anchor that terminates the path.
fn issuer_is_authorized(cert_der: &[u8], cas_below: u8, leaf_dns: &[String]) -> Result<bool, IkeError> {
    if !path_len_ok(basic_constraints(cert_der)?.and_then(|bc| bc.path_len_constraint), cas_below) {
        return Ok(false);
    }
    if !key_cert_sign_ok(key_usage(cert_der)?.as_ref()) {
        return Ok(false);
    }
    if let Some(nc) = name_constraints(cert_der)? {
        if !name_constraints_allow(&nc, leaf_dns) {
            return Ok(false);
        }
    }
    Ok(true)
}

/// DER of a certificate's subject distinguished name — RFC 7296's
/// `ID_DER_ASN1_DN` (value 9) IDi/IDr content for a certificate-authenticated
/// peer whose identity a gateway policy matches against the cert's Subject
/// DN rather than an arbitrary configured string (confirmed against a real
/// FortiGate: it rejected `ID_KEY_ID` carrying an unrelated username with
/// "gw validation failed" once a client certificate was in play). Also reused
/// as-is by IKEv1 Main Mode RSA-sig auth (RFC 2409 §5.1's `ID_DER_ASN1_DN`),
/// which encodes identically.
pub fn cert_subject_dn(cert_der: &[u8]) -> Result<Vec<u8>, IkeError> {
    subject_dn(cert_der)
}

/// Human-readable (RFC 4514) subject/issuer strings, for `AuthFailed`
/// diagnostics only -- callers that need the DER form for chain-building use
/// [`cert_subject_dn`]/the crate-private `subject_dn`/`issuer_dn` instead.
pub fn cert_subject_issuer_display(cert_der: &[u8]) -> Result<(String, String), IkeError> {
    use der::Decode;
    let cert = x509_cert::Certificate::from_der(cert_der).map_err(|_| IkeError::Crypto("malformed certificate DER"))?;
    Ok((cert.tbs_certificate.subject.to_string(), cert.tbs_certificate.issuer.to_string()))
}

/// DER of a certificate's subject / issuer distinguished name (for chaining).
fn subject_dn(cert_der: &[u8]) -> Result<Vec<u8>, IkeError> {
    use der::{Decode, Encode};
    let cert = x509_cert::Certificate::from_der(cert_der)
        .map_err(|_| IkeError::Crypto("malformed certificate DER"))?;
    cert.tbs_certificate.subject.to_der().map_err(|_| IkeError::Crypto("bad subject DN"))
}
fn issuer_dn(cert_der: &[u8]) -> Result<Vec<u8>, IkeError> {
    use der::{Decode, Encode};
    let cert = x509_cert::Certificate::from_der(cert_der)
        .map_err(|_| IkeError::Crypto("malformed certificate DER"))?;
    cert.tbs_certificate.issuer.to_der().map_err(|_| IkeError::Crypto("bad issuer DN"))
}

fn within_validity(cert_der: &[u8], now_unix: u64) -> Result<(), IkeError> {
    let (not_before, not_after) = cert_validity(cert_der)?;
    if now_unix < not_before || now_unix > not_after {
        return Err(IkeError::AuthFailed);
    }
    Ok(())
}

/// Build and validate an X.509 path from `leaf_der` up to one of `anchors`,
/// using `intermediates` (leaf and each intermediate must be within their
/// validity window at `now_unix`; each non-anchor issuer must be a CA). This
/// is signature + validity + BasicConstraints(CA) + `pathLenConstraint` +
/// KeyUsage(keyCertSign) validation, plus NameConstraints enforcement scoped
/// to the leaf's own SAN dNSNames (see `name_constraints_allow`'s doc). It
/// does **not** check EKU, critical-extension recognition, certificate
/// policy processing, or revocation (CRL/OCSP) — the last needs network
/// access a library cannot assume.
pub fn validate_chain(
    leaf_der: &[u8],
    intermediates: &[Vec<u8>],
    anchors: &[Vec<u8>],
    now_unix: u64,
) -> Result<(), IkeError> {
    let leaf_dns = cert_dns_names(leaf_der)?;
    let mut current = leaf_der.to_vec();
    // Number of non-self-issued intermediate CA certs already accepted
    // between the issuer now being considered and the leaf (RFC 5280
    // §4.2.1.9's pathLenConstraint counts exactly this).
    let mut cas_below: u8 = 0;
    // At most one hop per intermediate, plus the final hop to an anchor.
    for _ in 0..=intermediates.len() {
        within_validity(&current, now_unix)?;
        let want_issuer = issuer_dn(&current)?;

        // Reaching a trust anchor that issued `current` terminates the path.
        for anchor in anchors {
            if subject_dn(anchor)? == want_issuer
                && verify_cert_signed_by(&current, anchor).is_ok()
                && matches!(issuer_is_authorized(anchor, cas_below, &leaf_dns), Ok(true))
            {
                return Ok(());
            }
        }
        // Otherwise step up through an intermediate CA that issued `current`.
        let next = intermediates.iter().find(|inter| {
            subject_dn(inter).ok().as_deref() == Some(&want_issuer)
                && matches!(cert_is_ca(inter), Ok(true))
                && matches!(issuer_is_authorized(inter, cas_below, &leaf_dns), Ok(true))
                && verify_cert_signed_by(&current, inter).is_ok()
        });
        match next {
            Some(inter) => {
                current = inter.clone();
                cas_below += 1;
            }
            None => return Err(IkeError::AuthFailed),
        }
    }
    Err(IkeError::AuthFailed)
}

/// The full peer-certificate check for cert-based auth: the leaf must be
/// trusted (pinned exactly in `trusted`, or chain to one of the trusted
/// anchors through `intermediates`), be within validity, vouch for
/// `expected_dns` if given, and carry a signature over `signed_octets` that
/// verifies under its key. `auth_method` selects the AUTH payload's wire
/// format: RFC 7427 Digital Signature (14, self-describing algorithm) or the
/// classic RFC 7296 §3.8 method 1 (RSA Digital Signature, a bare PKCS#1 v1.5
/// signature) — a real FortiGate ("Certificates + EAP") sends method 1, not
/// 14, live-confirmed.
#[allow(clippy::too_many_arguments)]
pub fn verify_cert_auth(
    leaf_der: &[u8],
    intermediates: &[Vec<u8>],
    trusted: &[Vec<u8>],
    expected_dns: Option<&str>,
    now_unix: u64,
    auth_method: u8,
    auth_data: &[u8],
    signed_octets: &[u8],
) -> Result<(), IkeError> {
    // Trust: exact pin, or a validated path to an anchor.
    if trusted.iter().any(|t| t.as_slice() == leaf_der) {
        within_validity(leaf_der, now_unix)?;
    } else {
        validate_chain(leaf_der, intermediates, trusted, now_unix)?;
    }
    // Identity binding.
    if let Some(name) = expected_dns {
        if !matches!(cert_has_dns_name(leaf_der, name), Ok(true)) {
            return Err(IkeError::AuthFailed);
        }
    }
    // The AUTH signature must verify under the leaf's key.
    let vk = VerifyingKey::from_cert_der(leaf_der)?;
    match auth_method {
        crate::ikev2::payload::auth_method::DIGITAL_SIGNATURE => vk.verify_auth_data(auth_data, signed_octets),
        crate::ikev2::payload::auth_method::RSA_SIG => vk.verify_classic_rsa_auth_data(auth_data, signed_octets),
        _ => Err(IkeError::Crypto("unsupported AUTH method for certificate verification")),
    }
}

/// The SHA-1 of a certificate's DER `SubjectPublicKeyInfo` — the trust-anchor
/// identifier concatenated in a CERTREQ payload (RFC 7296 §3.7). Note this
/// hashes the whole SPKI SEQUENCE, not just the key bits.
pub fn ca_key_hash(cert_der: &[u8]) -> Result<[u8; 20], IkeError> {
    use der::{Decode, Encode};
    let cert = x509_cert::Certificate::from_der(cert_der)
        .map_err(|_| IkeError::Crypto("malformed certificate DER"))?;
    let spki_der = cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|_| IkeError::Crypto("malformed SPKI"))?;
    Ok(sha1::Sha1::digest(&spki_der).into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_certs::{CA_CERT_DER, LEAF_CERT_DER, LEAF_SCALAR, RSA_KEY_PK8};

    fn ecdsa_leaf_signer() -> SigningKey {
        SigningKey::EcdsaP256(p256::ecdsa::SigningKey::from_slice(LEAF_SCALAR).unwrap())
    }

    fn rsa_signer() -> (SigningKey, VerifyingKey) {
        use rsa::pkcs8::DecodePrivateKey;
        let key = rsa::RsaPrivateKey::from_pkcs8_der(RSA_KEY_PK8).unwrap();
        let pubk = key.to_public_key();
        (SigningKey::RsaSha256(Box::new(key)), VerifyingKey::Rsa(pubk))
    }

    #[test]
    fn algorithm_identifier_lengths_match_the_der() {
        assert_eq!(sig_alg::RSA_SHA256.len(), 15);
        assert_eq!(sig_alg::ECDSA_P256_SHA256.len(), 12);
        // Full DER SEQUENCE: 0x30 0x41 (2) + 65 content octets = 67.
        assert_eq!(sig_alg::RSA_PSS_SHA256.len(), 67);
        assert_eq!(sig_alg::RSA_PSS_SHA256[1], 0x41); // inner content length
    }

    #[test]
    fn ecdsa_sign_verify_roundtrip_via_certificate_key() {
        let signer = ecdsa_leaf_signer();
        let octets = b"ResponderSignedOctets: msgR | Ni | prf(SK_pr, IDr)";
        let auth = signer.sign_auth_data(octets).unwrap();
        // The AUTH data carries the ecdsa-with-SHA256 AlgorithmIdentifier.
        let (alg, _sig) = parse_auth_data(&auth).unwrap();
        assert_eq!(alg, sig_alg::ECDSA_P256_SHA256);
        // The public key recovered from the leaf CERT verifies it.
        let vk = VerifyingKey::from_cert_der(LEAF_CERT_DER).unwrap();
        vk.verify_auth_data(&auth, octets).unwrap();
        // Tampered octets fail.
        assert!(vk.verify_auth_data(&auth, b"different octets").is_err());
        // A single flipped signature byte fails.
        let mut bad = auth.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(vk.verify_auth_data(&bad, octets).is_err());
    }

    #[test]
    fn rsa_pkcs1v15_sign_verify_roundtrip() {
        let (signer, verifier) = rsa_signer();
        assert_eq!(signer.algorithm_id(), sig_alg::RSA_SHA256);
        let octets = b"InitiatorSignedOctets under RSA";
        let auth = signer.sign_auth_data(octets).unwrap();
        verifier.verify_auth_data(&auth, octets).unwrap();
        assert!(verifier.verify_auth_data(&auth, b"tampered").is_err());
    }

    #[test]
    fn classic_rsa_method1_auth_verifies_sha256_and_sha1_and_rejects_tampering() {
        // RFC 7296 §3.8 method 1 ("RSA Digital Signature") has no in-band hash
        // indicator -- a real FortiGate configured for "Certificates + EAP"
        // sends this method (not 14) live-signed with SHA-256, but the
        // original RFC 2409/4306 text assumed SHA-1, so both must verify.
        use rsa::pkcs8::DecodePrivateKey;
        use sha1::Sha1;
        let key = rsa::RsaPrivateKey::from_pkcs8_der(RSA_KEY_PK8).unwrap();
        let pubk = VerifyingKey::Rsa(key.to_public_key());
        let octets = b"ResponderSignedOctets under classic RSA method 1";

        let sig256 = key.sign(rsa::Pkcs1v15Sign::new::<Sha256>(), &Sha256::digest(octets)).unwrap();
        pubk.verify_classic_rsa_auth_data(&sig256, octets).unwrap();

        let sig1 = key.sign(rsa::Pkcs1v15Sign::new::<Sha1>(), &Sha1::digest(octets)).unwrap();
        pubk.verify_classic_rsa_auth_data(&sig1, octets).unwrap();

        assert!(pubk.verify_classic_rsa_auth_data(&sig256, b"different octets").is_err());
        // An RFC 7427-wrapped (method 14) blob is not a bare signature and must not verify as one.
        let wrapped = SigningKey::RsaSha256(Box::new(key)).sign_auth_data(octets).unwrap();
        assert!(pubk.verify_classic_rsa_auth_data(&wrapped, octets).is_err());
    }

    #[test]
    fn classic_rsa_raw_sign_verify_roundtrips_and_rejects_tampering_and_prefixed_signatures() {
        // The IKEv1 SIG-payload primitive (RFC 2409 §5.1): signs `data`
        // directly (here, a stand-in for an already-computed HASH_I/HASH_R),
        // with no re-hashing and no DigestInfo prefix -- distinct from
        // `sign_auth_data`/`verify_classic_rsa_auth_data` above, which both
        // re-hash the input first.
        let (signer, verifier) = rsa_signer();
        let hash_i = b"a stand-in for crypto1::hash_i's 32-byte SHA-256 output"; // arbitrary length is fine -- unprefixed
        let sig = signer.sign_classic_rsa_raw(hash_i).unwrap();
        verifier.verify_classic_rsa_raw(&sig, hash_i).unwrap();
        assert!(verifier.verify_classic_rsa_raw(&sig, b"tampered").is_err());

        // A signature made by the prefixed method-1 scheme must not verify
        // under the raw/unprefixed verifier -- the two must not cross-accept
        // each other's signatures.
        use rsa::pkcs8::DecodePrivateKey;
        let key = rsa::RsaPrivateKey::from_pkcs8_der(RSA_KEY_PK8).unwrap();
        let via_method1 = key.sign(rsa::Pkcs1v15Sign::new::<Sha256>(), &Sha256::digest(hash_i)).unwrap();
        assert!(verifier.verify_classic_rsa_raw(&via_method1, hash_i).is_err());

        // Neither side of a classic RSA SIG payload works with an ECDSA key.
        let ec_signer = SigningKey::EcdsaP256(p256::ecdsa::SigningKey::from_slice(LEAF_SCALAR).unwrap());
        assert!(ec_signer.sign_classic_rsa_raw(hash_i).is_err());
        let ec_vk = VerifyingKey::from_cert_der(LEAF_CERT_DER).unwrap();
        assert!(ec_vk.verify_classic_rsa_raw(&sig, hash_i).is_err());
    }

    #[test]
    fn key_and_scheme_must_agree() {
        // An RSA signature presented for verification by an ECDSA cert key fails
        // cleanly rather than misverifying.
        let (rsa_signer, _rsa_vk) = rsa_signer();
        let octets = b"octets";
        let rsa_auth = rsa_signer.sign_auth_data(octets).unwrap();
        let ec_vk = VerifyingKey::from_cert_der(LEAF_CERT_DER).unwrap();
        assert!(ec_vk.verify_auth_data(&rsa_auth, octets).is_err());
    }

    #[test]
    fn chain_verification_accepts_real_issuer_and_rejects_others() {
        // The leaf really was signed by the CA.
        verify_cert_signed_by(LEAF_CERT_DER, CA_CERT_DER).unwrap();
        // The leaf was not signed by itself.
        assert!(verify_cert_signed_by(LEAF_CERT_DER, LEAF_CERT_DER).is_err());
        // The CA is self-signed (sanity: it verifies under its own key).
        verify_cert_signed_by(CA_CERT_DER, CA_CERT_DER).unwrap();
    }

    #[test]
    fn ca_key_hash_is_20_bytes_and_stable() {
        let h1 = ca_key_hash(CA_CERT_DER).unwrap();
        let h2 = ca_key_hash(CA_CERT_DER).unwrap();
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 20);
        // Leaf and CA have different keys → different hashes.
        assert_ne!(ca_key_hash(LEAF_CERT_DER).unwrap(), h1);
    }

    #[test]
    fn rsa_from_pkcs8_der_signs_like_a_directly_constructed_key() {
        use rsa::pkcs1::EncodeRsaPrivateKey;
        let key = SigningKey::rsa_from_pkcs8_der(RSA_KEY_PK8).unwrap();
        assert_eq!(key.algorithm_id(), sig_alg::RSA_SHA256);
        let (_, verifier) = rsa_signer();
        let octets = b"octets signed by a PKCS#8-loaded RSA key";
        verifier.verify_auth_data(&key.sign_auth_data(octets).unwrap(), octets).unwrap();

        // Round-trip through PKCS#1 DER (the traditional `BEGIN RSA PRIVATE
        // KEY` form) and confirm it loads and signs identically.
        use rsa::pkcs8::DecodePrivateKey;
        let pkcs8_key = rsa::RsaPrivateKey::from_pkcs8_der(RSA_KEY_PK8).unwrap();
        let pkcs1_der = pkcs8_key.to_pkcs1_der().unwrap();
        let key1 = SigningKey::rsa_from_pkcs1_der(pkcs1_der.as_bytes()).unwrap();
        verifier.verify_auth_data(&key1.sign_auth_data(octets).unwrap(), octets).unwrap();
    }

    #[test]
    fn parse_auth_data_rejects_truncation() {
        assert!(parse_auth_data(&[]).is_err());
        assert!(parse_auth_data(&[0x0c, 0x30, 0x0a]).is_err()); // claims 12, has 2
    }

    #[test]
    fn chain_building_dates_and_basic_constraints() {
        use crate::test_certs::{CHAIN_INT_DER, CHAIN_LEAF_DER, CHAIN_ROOT_DER};
        let (nb, na) = cert_validity(CHAIN_LEAF_DER).unwrap();
        let now = nb + 1;

        // Full path leaf -> intermediate -> root validates.
        validate_chain(CHAIN_LEAF_DER, &[CHAIN_INT_DER.to_vec()], &[CHAIN_ROOT_DER.to_vec()], now).unwrap();
        // Missing the intermediate → no path to the anchor.
        assert!(validate_chain(CHAIN_LEAF_DER, &[], &[CHAIN_ROOT_DER.to_vec()], now).is_err());
        // Trusting the intermediate directly (as an anchor) also validates.
        validate_chain(CHAIN_LEAF_DER, &[], &[CHAIN_INT_DER.to_vec()], now).unwrap();
        // Expired / not-yet-valid are rejected.
        assert!(validate_chain(CHAIN_LEAF_DER, &[CHAIN_INT_DER.to_vec()], &[CHAIN_ROOT_DER.to_vec()], na + 1).is_err());
        assert!(validate_chain(CHAIN_LEAF_DER, &[CHAIN_INT_DER.to_vec()], &[CHAIN_ROOT_DER.to_vec()], nb - 1).is_err());
        // The intermediate is a CA; the leaf is not.
        assert!(cert_is_ca(CHAIN_INT_DER).unwrap());
        assert!(!cert_is_ca(CHAIN_LEAF_DER).unwrap());
        // A non-CA cannot act as an intermediate issuer.
        assert!(validate_chain(CHAIN_LEAF_DER, &[CHAIN_LEAF_DER.to_vec()], &[CHAIN_ROOT_DER.to_vec()], now).is_err());
    }

    #[test]
    fn chain_validates_even_when_the_peer_also_sends_the_self_signed_root() {
        // Some gateways (a real FortiGate, live-tested) attach their own
        // trust-anchor cert as an extra trailing "intermediate" alongside the
        // real chain -- e.g. leaf -> int -> root, with the self-signed root
        // itself included as the last CERT payload. The anchor-match check
        // must still terminate one hop early via `anchors`, not get stuck
        // trying to chain through the self-signed cert as an intermediate.
        use crate::test_certs::{CHAIN_INT_DER, CHAIN_LEAF_DER, CHAIN_ROOT_DER};
        let (nb, _na) = cert_validity(CHAIN_LEAF_DER).unwrap();
        let now = nb + 1;
        validate_chain(
            CHAIN_LEAF_DER,
            &[CHAIN_INT_DER.to_vec(), CHAIN_ROOT_DER.to_vec()],
            &[CHAIN_ROOT_DER.to_vec()],
            now,
        )
        .unwrap();
    }

    #[test]
    fn direct_leaf_to_anchor_still_validates() {
        // The simple two-cert fixtures: leaf issued straight off the CA anchor.
        let (nb, _na) = cert_validity(LEAF_CERT_DER).unwrap();
        validate_chain(LEAF_CERT_DER, &[], &[CA_CERT_DER.to_vec()], nb + 1).unwrap();
    }

    #[test]
    fn path_len_ok_enforces_the_pathlenconstraint_boundary() {
        assert!(path_len_ok(None, 0));
        assert!(path_len_ok(None, 200)); // unconstrained allows any depth
        assert!(path_len_ok(Some(0), 0));
        assert!(!path_len_ok(Some(0), 1));
        assert!(path_len_ok(Some(2), 2));
        assert!(!path_len_ok(Some(1), 2));
    }

    #[test]
    fn key_cert_sign_ok_requires_the_bit_only_when_keyusage_is_present() {
        use x509_cert::ext::pkix::{KeyUsage, KeyUsages};
        assert!(key_cert_sign_ok(None)); // omitted extension is permissive
        let with_bit = KeyUsage(KeyUsages::KeyCertSign.into());
        assert!(key_cert_sign_ok(Some(&with_bit)));
        let without_bit = KeyUsage(KeyUsages::DigitalSignature.into());
        assert!(!key_cert_sign_ok(Some(&without_bit)));
    }

    #[test]
    fn dns_name_within_base_matches_exact_and_subdomains_but_not_bare_substrings() {
        assert!(dns_name_within_base("example.com", "example.com"));
        assert!(dns_name_within_base("host.example.com", "example.com"));
        assert!(dns_name_within_base("a.b.example.com", "example.com"));
        assert!(dns_name_within_base("EXAMPLE.com", "example.COM")); // case-insensitive
        // A bare substring match (no dot boundary) must not count as a subdomain.
        assert!(!dns_name_within_base("evilexample.com", "example.com"));
        assert!(!dns_name_within_base("example.com.evil.net", "example.com"));
        assert!(!dns_name_within_base("other.com", "example.com"));
        assert!(!dns_name_within_base("com", "example.com")); // shorter than base
    }

    #[test]
    fn name_constraints_allow_enforces_excluded_and_permitted_dns_subtrees() {
        use x509_cert::ext::pkix::constraints::name::GeneralSubtree;
        use x509_cert::ext::pkix::name::GeneralName;
        use x509_cert::ext::pkix::NameConstraints;

        fn dns_subtree(name: &str) -> GeneralSubtree {
            GeneralSubtree {
                base: GeneralName::DnsName(der::asn1::Ia5String::new(name).unwrap()),
                minimum: 0,
                maximum: None,
            }
        }

        // Excluded subtree rejects a matching leaf name.
        let excluded = NameConstraints {
            permitted_subtrees: None,
            excluded_subtrees: Some(vec![dns_subtree("example.com")]),
        };
        assert!(!name_constraints_allow(&excluded, &["vpn.example.com".to_string()]));
        assert!(name_constraints_allow(&excluded, &["vpn.other.com".to_string()]));

        // Permitted subtree allows only in-domain names.
        let permitted = NameConstraints {
            permitted_subtrees: Some(vec![dns_subtree("example.com")]),
            excluded_subtrees: None,
        };
        assert!(name_constraints_allow(&permitted, &["vpn.example.com".to_string()]));
        assert!(!name_constraints_allow(&permitted, &["vpn.other.com".to_string()]));

        // A non-dNSName-typed subtree doesn't restrict dNSName matching.
        let other_type = NameConstraints {
            permitted_subtrees: Some(vec![GeneralSubtree {
                base: GeneralName::Rfc822Name(der::asn1::Ia5String::new("user@example.com").unwrap()),
                minimum: 0,
                maximum: None,
            }]),
            excluded_subtrees: None,
        };
        assert!(name_constraints_allow(&other_type, &["vpn.other.com".to_string()]));

        // No leaf dNSNames at all is vacuously permitted.
        assert!(name_constraints_allow(&permitted, &[]));
    }

    #[test]
    fn chain_rejects_a_path_deeper_than_the_roots_pathlenconstraint() {
        use crate::test_certs::{PATHLEN_INT_DER, PATHLEN_LEAF_DER, PATHLEN_ROOT_DER};
        let (nb, _na) = cert_validity(PATHLEN_LEAF_DER).unwrap();
        let now = nb + 1;
        // PATHLEN_ROOT asserts pathlen:0, but there's one intermediate below it.
        assert!(validate_chain(
            PATHLEN_LEAF_DER,
            &[PATHLEN_INT_DER.to_vec()],
            &[PATHLEN_ROOT_DER.to_vec()],
            now
        )
        .is_err());
        // Trusting the intermediate directly still validates -- the check is
        // scoped to pathLenConstraint, not a blanket rejection of the chain.
        validate_chain(PATHLEN_LEAF_DER, &[], &[PATHLEN_INT_DER.to_vec()], now).unwrap();
    }

    #[test]
    fn chain_rejects_an_issuer_whose_keyusage_omits_keycertsign() {
        use crate::test_certs::{CONSTRAINT_ROOT_DER, NOKCS_INT_DER, NOKCS_LEAF_DER};
        let (nb, _na) = cert_validity(NOKCS_LEAF_DER).unwrap();
        let now = nb + 1;
        assert!(validate_chain(
            NOKCS_LEAF_DER,
            &[NOKCS_INT_DER.to_vec()],
            &[CONSTRAINT_ROOT_DER.to_vec()],
            now
        )
        .is_err());
    }

    #[test]
    fn chain_rejects_a_leaf_name_the_issuer_name_constraints_exclude() {
        use crate::test_certs::{CONSTRAINT_ROOT_DER, EXCLUDED_INT_DER, EXCLUDED_LEAF_DER};
        let (nb, _na) = cert_validity(EXCLUDED_LEAF_DER).unwrap();
        let now = nb + 1;
        assert!(validate_chain(
            EXCLUDED_LEAF_DER,
            &[EXCLUDED_INT_DER.to_vec()],
            &[CONSTRAINT_ROOT_DER.to_vec()],
            now
        )
        .is_err());
    }

    #[test]
    fn cert_subject_dn_is_der_and_round_trips_through_x509_cert() {
        use der::Decode;
        let dn = cert_subject_dn(LEAF_CERT_DER).unwrap();
        // Must be the exact TBSCertificate.subject field, re-parseable as a Name.
        let parsed = x509_cert::name::Name::from_der(&dn).unwrap();
        let cert = x509_cert::Certificate::from_der(LEAF_CERT_DER).unwrap();
        assert_eq!(parsed, cert.tbs_certificate.subject);
        // Leaf and CA have different subjects.
        assert_ne!(cert_subject_dn(LEAF_CERT_DER).unwrap(), cert_subject_dn(CA_CERT_DER).unwrap());
    }

    #[test]
    fn san_dns_name_matching() {
        // The leaf fixture has SAN dNSName=vpn.example.com.
        assert!(cert_has_dns_name(LEAF_CERT_DER, "vpn.example.com").unwrap());
        assert!(cert_has_dns_name(LEAF_CERT_DER, "VPN.Example.COM").unwrap()); // case-insensitive
        assert!(!cert_has_dns_name(LEAF_CERT_DER, "evil.example.com").unwrap());
        assert!(!cert_has_dns_name(LEAF_CERT_DER, "example.com").unwrap()); // no suffix match
        // The CA fixture has no SAN.
        assert!(!cert_has_dns_name(CA_CERT_DER, "vpn.example.com").unwrap());
    }
}
