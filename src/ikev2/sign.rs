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
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::{BasicConstraints, KeyUsage, NameConstraints, SubjectAltName};

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
    /// Signature (a native EAP client that sends no SIGNATURE_HASH_ALGORITHMS)
    /// and our key is ECDSA. An RSA key in that same situation must use
    /// [`Self::sign_classic_rsa_auth_data`] (method 1) instead -- see
    /// `crate::ikev2::ike_auth::cert_auth_payload`, which picks between the two
    /// by key type.
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

    /// Sign as the classic RFC 7296 §3.8 method-1 AUTH (RSA Digital
    /// Signature): a plain PKCS#1 v1.5 signature, `DigestInfo`-prefixed, over
    /// `SHA-256(signed_octets)` -- no RFC 7427 algorithm wrapper, unlike
    /// method 14. This is the RSA counterpart to
    /// [`Self::sign_ecdsa_p256_raw`]'s method 9: the fallback
    /// `cert_auth_payload` picks when the peer hasn't negotiated Digital
    /// Signature and our key is RSA rather than ECDSA. Not to be confused
    /// with [`Self::sign_classic_rsa_raw`], the *unprefixed* IKEv1 SIG
    /// payload convention.
    pub fn sign_classic_rsa_auth_data(&self, signed_octets: &[u8]) -> Result<Vec<u8>, IkeError> {
        match self {
            SigningKey::RsaSha256(key) => {
                let digest = Sha256::digest(signed_octets);
                key.sign(rsa::Pkcs1v15Sign::new::<Sha256>(), &digest)
                    .map_err(|_| IkeError::Crypto("RSA signing failed"))
            }
            SigningKey::EcdsaP256(_) => {
                Err(IkeError::Crypto("method 1 (RSA Digital Signature) needs an RSA certificate key"))
            }
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

    /// Verify a classic IKEv2 method-9 AUTH (ECDSA-256, RFC 4754): `sig` is
    /// the raw `r || s` (64 bytes for P-256) over `SHA-256(signed_octets)`,
    /// with no RFC 7427 algorithm wrapper -- the counterpart to
    /// `SigningKey::sign_ecdsa_p256_raw`. Without this, a peer emitting
    /// method 9 (e.g. because it didn't see our SIGNATURE_HASH_ALGORITHMS,
    /// mirroring why we ourselves emit it in `cert_auth_payload`) could
    /// never be verified, even though we produce that exact wire format
    /// ourselves.
    pub fn verify_ecdsa_p256_raw(&self, sig: &[u8], signed_octets: &[u8]) -> Result<(), IkeError> {
        let VerifyingKey::EcdsaP256(vk) = self else {
            return Err(IkeError::Crypto("method 9 (ECDSA Digital Signature) needs an EC certificate key"));
        };
        use p256::ecdsa::signature::hazmat::PrehashVerifier;
        let sig = p256::ecdsa::Signature::from_slice(sig).map_err(|_| IkeError::AuthFailed)?;
        let digest = Sha256::digest(signed_octets);
        vk.verify_prehash(&digest, &sig).map_err(|_| IkeError::AuthFailed)
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

/// One certificate, decoded once, with the extensions this module
/// processes. Decoding applies RFC 5280 §4.2 to every certificate the
/// module relies on -- a pinned one, the leaf, each intermediate taken and
/// the trust anchor that ends the path:
/// - an extension may appear only once ("MUST NOT include more than one
///   instance of a particular extension");
/// - each extension read here must decode, critical or not (a recognized
///   non-critical extension "MUST be processed");
/// - a critical extension not read here rejects the certificate ("MUST
///   reject the certificate if it encounters a critical extension it does
///   not recognize").
///
/// The last covers ExtendedKeyUsage and the certificate-policy extensions.
/// RFC 4945 §5.1.3.12 does not require IKE to support EKU, and this crate
/// does no policy processing, so they reject the certificate when critical
/// and are ignored when not.
struct ParsedCert {
    tbs: x509_cert::certificate::TbsCertificate,
    basic_constraints: Option<BasicConstraints>,
    key_usage: Option<KeyUsage>,
    subject_alt_name: Option<SubjectAltName>,
    name_constraints: Option<NameConstraints>,
}

/// pkcs-9 emailAddress (RFC 5280 §4.1.2.6), an IA5String.
const OID_EMAIL_ADDRESS: der::asn1::ObjectIdentifier = der::asn1::ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.1");

impl ParsedCert {
    fn from_der(cert_der: &[u8]) -> Result<ParsedCert, IkeError> {
        use der::oid::AssociatedOid;
        use der::{Decode, DecodeOwned};
        fn decode<T: DecodeOwned>(ext: &x509_cert::ext::Extension, what: &'static str) -> Result<Option<T>, IkeError> {
            T::from_der(ext.extn_value.as_bytes()).map(Some).map_err(|_| IkeError::Crypto(what))
        }
        let tbs = x509_cert::Certificate::from_der(cert_der).map_err(|_| IkeError::Crypto("malformed certificate DER"))?.tbs_certificate;
        let (mut basic_constraints, mut key_usage, mut subject_alt_name, mut name_constraints) = (None, None, None, None);
        let exts = tbs.extensions.as_deref().unwrap_or_default();
        for (i, ext) in exts.iter().enumerate() {
            if exts[..i].iter().any(|seen| seen.extn_id == ext.extn_id) {
                return Err(IkeError::Crypto("certificate repeats an extension"));
            }
            if ext.extn_id == BasicConstraints::OID {
                basic_constraints = decode(ext, "malformed BasicConstraints")?;
            } else if ext.extn_id == KeyUsage::OID {
                key_usage = decode(ext, "malformed KeyUsage")?;
            } else if ext.extn_id == SubjectAltName::OID {
                subject_alt_name = decode(ext, "malformed SubjectAltName")?;
            } else if ext.extn_id == NameConstraints::OID {
                name_constraints = decode(ext, "malformed NameConstraints")?;
            } else if ext.critical {
                return Err(IkeError::Crypto("certificate has a critical extension this crate does not process"));
            }
        }
        Ok(ParsedCert { tbs, basic_constraints, key_usage, subject_alt_name, name_constraints })
    }

    fn is_ca(&self) -> bool {
        self.basic_constraints.as_ref().is_some_and(|bc| bc.ca)
    }

    /// RFC 5280 §6.1: self-issued when the subject and issuer names are
    /// the same. They are compared as encoded, so a name that §7.1 would
    /// call the same under another encoding counts as not self-issued, the
    /// stricter side.
    fn is_self_issued(&self) -> bool {
        self.tbs.subject == self.tbs.issuer
    }

    /// The SubjectAltName dNSName entries, verbatim.
    fn dns_names(&self) -> impl Iterator<Item = &str> {
        self.subject_alt_name.iter().flat_map(|san| &san.0).filter_map(|name| match name {
            GeneralName::DnsName(dns) => Some(dns.as_str()),
            _ => None,
        })
    }

    /// The names a CA's NameConstraints apply to here (RFC 5280
    /// §4.2.1.10): the subject when it is not empty, every SubjectAltName
    /// entry, and each emailAddress attribute of the subject, as an
    /// rfc822Name. The RFC requires the last only without a
    /// SubjectAltName; holding it always is the stricter reading.
    fn constrained_names(&self) -> Vec<GeneralName> {
        let subject = &self.tbs.subject;
        let mut names: Vec<GeneralName> = self.subject_alt_name.iter().flat_map(|san| san.0.iter().cloned()).collect();
        if !subject.0.is_empty() {
            names.push(GeneralName::DirectoryName(subject.clone()));
        }
        for email in subject.0.iter().flat_map(|rdn| rdn.0.iter()).filter(|atv| atv.oid == OID_EMAIL_ADDRESS) {
            // One that is not an IA5String becomes a mailbox without an
            // "@", which no rfc822Name subtree can place, so such a subtree
            // rejects the certificate instead of passing it.
            let mailbox = email.value.decode_as::<der::asn1::Ia5String>().unwrap_or_else(|_| der::asn1::Ia5String::new("").unwrap());
            names.push(GeneralName::Rfc822Name(mailbox));
        }
        names
    }
}

/// Whether the certificate's `SubjectAltName` contains `name` as a dNSName
/// (exact, ASCII-case-insensitive; wildcards are not expanded). Modern
/// iOS/Android bind the server identity this way — a valid cert for one host
/// must not authenticate another, so callers doing cert auth must check this.
pub fn cert_has_dns_name(cert_der: &[u8], name: &str) -> Result<bool, IkeError> {
    Ok(ParsedCert::from_der(cert_der)?.dns_names().any(|dns| dns.eq_ignore_ascii_case(name)))
}

/// A certificate's `(notBefore, notAfter)` as Unix seconds.
pub fn cert_validity(cert_der: &[u8]) -> Result<(u64, u64), IkeError> {
    use der::Decode;
    let cert = x509_cert::Certificate::from_der(cert_der)
        .map_err(|_| IkeError::Crypto("malformed certificate DER"))?;
    let v = &cert.tbs_certificate.validity;
    Ok((v.not_before.to_unix_duration().as_secs(), v.not_after.to_unix_duration().as_secs()))
}

/// Whether a certificate asserts `BasicConstraints` with `CA:TRUE`.
pub fn cert_is_ca(cert_der: &[u8]) -> Result<bool, IkeError> {
    Ok(ParsedCert::from_der(cert_der)?.is_ca())
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

/// Where a name stands against one NameConstraints subtree of its own form.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Within {
    Yes,
    No,
    /// A form this module does not process, or a name or subtree it cannot
    /// read: rejects in a permitted subtree and in an excluded one alike.
    Unknown,
}

impl From<bool> for Within {
    fn from(within: bool) -> Within {
        if within {
            Within::Yes
        } else {
            Within::No
        }
    }
}

/// RFC 5280 §4.2.1.10 rfc822Name: a subtree is one mailbox ("user@host"),
/// every mailbox at one host ("host"), or every mailbox in a domain
/// (".example.com", not the host example.com itself). The host part
/// ignores case and the local part does not (§7.5).
fn mailbox_within(name: &str, base: &str) -> Within {
    let Some((local, host)) = name.rsplit_once('@') else { return Within::Unknown };
    match (base.rsplit_once('@'), base.strip_prefix('.')) {
        (Some((base_local, base_host)), _) => (local == base_local && host.eq_ignore_ascii_case(base_host)).into(),
        (None, Some(domain)) => (host.len() > domain.len() && dns_name_within_base(host, domain)).into(),
        (None, None) => host.eq_ignore_ascii_case(base).into(),
    }
}

/// RFC 5280 §4.2.1.10 iPAddress: a subtree is an address and a mask, 8
/// octets for IPv4 and 32 for IPv6, and a name is 4 or 16 octets. A name
/// of the other family is not within the subtree.
fn ip_within(name: &[u8], base: &[u8]) -> Within {
    match (name.len(), base.len()) {
        (4, 8) | (16, 32) => {
            let (address, mask) = base.split_at(name.len());
            name.iter().zip(address).zip(mask).all(|((n, a), m)| n & m == a & m).into()
        }
        (4 | 16, 8 | 32) => Within::No,
        _ => Within::Unknown,
    }
}

/// RFC 5280 §4.2.1.10 directoryName: `name` is within `base` when its
/// first RDNs are those of `base`.
fn dn_within(name: &x509_cert::name::Name, base: &x509_cert::name::Name) -> bool {
    base.0.len() <= name.0.len() && base.0.iter().zip(&name.0).all(|(b, n)| rdn_matches(b, n))
}

fn rdn_matches(a: &x509_cert::name::RelativeDistinguishedName, b: &x509_cert::name::RelativeDistinguishedName) -> bool {
    a.0.len() == b.0.len() && a.0.iter().all(|x| b.0.iter().any(|y| x.oid == y.oid && attribute_values_match(&x.value, &y.value)))
}

/// RFC 5280 §7.1 attribute value comparison, as far as this module takes
/// it. Values of the same encoding match. PrintableString and UTF8String
/// values -- and IA5String and VisibleString ones, whose attributes
/// (domainComponent, emailAddress) also ignore case -- match across those
/// types ignoring case and insignificant white space: RFC 4518's case
/// folding and space handling, without its Unicode normalization. Any other
/// value matches only as the same binary object, which §7.1 permits.
fn attribute_values_match(a: &der::Any, b: &der::Any) -> bool {
    fn text(value: &der::Any) -> Option<String> {
        use der::{Tag, Tagged};
        match value.tag() {
            Tag::Utf8String | Tag::PrintableString | Tag::Ia5String | Tag::VisibleString => {
                let text = std::str::from_utf8(value.value()).ok()?;
                Some(text.split_whitespace().collect::<Vec<_>>().join(" ").to_lowercase())
            }
            _ => None,
        }
    }
    a == b || matches!((text(a), text(b)), (Some(x), Some(y)) if x == y)
}

/// Where `name` stands against the subtree `base` of the same form.
/// dNSName, rfc822Name, iPAddress and directoryName subtrees are processed;
/// otherName, ediPartyName, uniformResourceIdentifier and registeredID ones
/// are not.
fn name_within(name: &GeneralName, base: &GeneralName) -> Within {
    match (name, base) {
        (GeneralName::DnsName(name), GeneralName::DnsName(base)) => dns_name_within_base(name.as_str(), base.as_str()).into(),
        (GeneralName::Rfc822Name(name), GeneralName::Rfc822Name(base)) => mailbox_within(name.as_str(), base.as_str()),
        (GeneralName::IpAddress(name), GeneralName::IpAddress(base)) => ip_within(name.as_bytes(), base.as_bytes()),
        (GeneralName::DirectoryName(name), GeneralName::DirectoryName(base)) => dn_within(name, base).into(),
        _ => Within::Unknown,
    }
}

/// RFC 5280 §4.2.1.10 and §6.1.3(b): whether `nc` allows every name in
/// `names` -- those of each certificate below the CA in the path (see
/// [`ParsedCert::constrained_names`]). A subtree restricts only names of
/// its own form: such a name must be within one permitted subtree of its
/// form when there are any, and within no excluded one. A name meeting a
/// subtree this cannot process rejects, as §4.2.1.10 has it: "the
/// application MUST either process the constraint or reject the
/// certificate". So does a subtree with a minimum or a maximum, which
/// "MUST be zero" and "MUST be absent".
fn name_constraints_allow(nc: &NameConstraints, names: &[GeneralName]) -> bool {
    use x509_cert::ext::pkix::constraints::name::GeneralSubtree;
    let permitted = nc.permitted_subtrees.as_deref().unwrap_or_default();
    let excluded = nc.excluded_subtrees.as_deref().unwrap_or_default();
    if permitted.iter().chain(excluded).any(|st| st.minimum != 0 || st.maximum.is_some()) {
        return false;
    }
    names.iter().all(|name| {
        let of_its_form = |st: &&GeneralSubtree| std::mem::discriminant(&st.base) == std::mem::discriminant(name);
        let mut permitted = permitted.iter().filter(of_its_form).peekable();
        excluded.iter().filter(of_its_form).all(|st| name_within(name, &st.base) == Within::No)
            && (permitted.peek().is_none() || permitted.any(|st| name_within(name, &st.base) == Within::Yes))
    })
}

/// Whether `issuer` may have issued what is below it in the path: its
/// `pathLenConstraint` (if any) allows `cas_below` non-self-issued
/// intermediates, its `KeyUsage` (if any) has keyCertSign, and its
/// `NameConstraints` (if any) allow `names`. Applied alike to accepted
/// intermediates and to the trust anchor that ends the path.
fn issuer_is_authorized(issuer: &ParsedCert, cas_below: u8, names: &[GeneralName]) -> bool {
    path_len_ok(issuer.basic_constraints.as_ref().and_then(|bc| bc.path_len_constraint), cas_below)
        && key_cert_sign_ok(issuer.key_usage.as_ref())
        && issuer.name_constraints.as_ref().is_none_or(|nc| name_constraints_allow(nc, names))
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
/// using `intermediates` -- chain validation, a subset of RFC 5280 §6.1:
/// - each certificate is signed by the next, the leaf and each
///   intermediate are within their validity at `now_unix`, and each
///   intermediate is a CA (BasicConstraints `CA:TRUE`);
/// - every certificate used, the anchor included, passes the extension
///   checks of RFC 5280 §4.2: no repeated extension, no malformed one it
///   reads, and no critical one it does not process (`ParsedCert`);
/// - each issuer, the anchor included, must allow what is below it:
///   `pathLenConstraint` counted over the non-self-issued intermediates
///   (§4.2.1.9, §6.1.4(l)), KeyUsage keyCertSign, and NameConstraints over
///   the names of the leaf and of every non-self-issued intermediate below
///   it (§6.1.3(b)) -- subject DNs, SubjectAltNames and subject
///   emailAddresses (`name_constraints_allow` says which forms).
///
/// Not checked here: whether the leaf may sign, which is
/// [`check_signing_key_usage`] (both in [`verify_cert_auth`]), whether it
/// names the peer, which is the caller's policy (`expected_dns` in
/// [`verify_cert_auth`]; RFC 4945 §3.1 ties an ID to a certificate field
/// only as the deployment chooses), ExtendedKeyUsage, certificate policies
/// and revocation (CRL/OCSP, which needs network access a library cannot
/// assume). Those are the consumer's to add.
pub fn validate_chain(
    leaf_der: &[u8],
    intermediates: &[Vec<u8>],
    anchors: &[Vec<u8>],
    now_unix: u64,
) -> Result<(), IkeError> {
    let leaf = ParsedCert::from_der(leaf_der)?;
    // The names every issuer's NameConstraints must allow: the leaf's, and
    // those of each non-self-issued intermediate taken so far.
    let mut names = leaf.constrained_names();
    let mut current: &[u8] = leaf_der;
    // Number of non-self-issued intermediate CA certs already accepted
    // between the issuer now being considered and the leaf (RFC 5280
    // §4.2.1.9's pathLenConstraint counts exactly this).
    let mut cas_below: u8 = 0;
    // At most one hop per intermediate, plus the final hop to an anchor.
    for _ in 0..=intermediates.len() {
        within_validity(current, now_unix)?;
        let want_issuer = issuer_dn(current)?;

        // Reaching a trust anchor that issued `current` terminates the path.
        for anchor in anchors {
            if subject_dn(anchor)? == want_issuer
                && verify_cert_signed_by(current, anchor).is_ok()
                && ParsedCert::from_der(anchor).is_ok_and(|anchor| issuer_is_authorized(&anchor, cas_below, &names))
            {
                return Ok(());
            }
        }
        // Otherwise step up through an intermediate CA that issued `current`.
        let next = intermediates.iter().find_map(|inter| {
            if subject_dn(inter).ok()? != want_issuer {
                return None;
            }
            let parsed = ParsedCert::from_der(inter).ok()?;
            (parsed.is_ca() && issuer_is_authorized(&parsed, cas_below, &names) && verify_cert_signed_by(current, inter).is_ok())
                .then_some((inter, parsed))
        });
        let Some((inter, parsed)) = next else { return Err(IkeError::AuthFailed) };
        // A self-issued intermediate neither counts toward a pathLenConstraint
        // (§6.1.4(l)) nor has its names constrained (§6.1.3(b)).
        if !parsed.is_self_issued() {
            cas_below = cas_below.saturating_add(1);
            names.extend(parsed.constrained_names());
        }
        current = inter;
    }
    Err(IkeError::AuthFailed)
}

/// RFC 4945 §5.1.3.2, for RFC 5280 §4.2.1.3's digitalSignature and
/// nonRepudiation: a certificate whose key is to verify the peer's
/// signature must, if it carries KeyUsage, assert at least one of the two
/// ("MUST be set"). Without KeyUsage its key may be used for anything. The
/// certificate must also pass the extension checks of [`validate_chain`].
/// [`verify_cert_auth`] applies it, and so does IKEv1's signature
/// authentication.
pub fn check_signing_key_usage(cert_der: &[u8]) -> Result<(), IkeError> {
    let cert = ParsedCert::from_der(cert_der)?;
    if cert.key_usage.is_none_or(|ku| ku.digital_signature() || ku.non_repudiation()) {
        Ok(())
    } else {
        Err(IkeError::AuthFailed)
    }
}

/// The full peer-certificate check for cert-based auth, in three parts:
/// - **trust**: the leaf is pinned exactly in `trusted` (explicit trust in
///   that one certificate: only its validity and the extension checks of
///   [`validate_chain`] apply), or chains to one of the trusted anchors
///   through `intermediates` ([`validate_chain`]);
/// - **use**: its KeyUsage allows verifying a signature
///   ([`check_signing_key_usage`]);
/// - **identity**: it vouches for `expected_dns`, if the caller's policy
///   gives one (RFC 4945 §3.1 leaves which ID binds to which certificate
///   field to the deployment, so nothing is required here without it).
///
/// Then its key must verify the signature over `signed_octets`.
/// `auth_method` selects the AUTH payload's wire format: RFC 7427 Digital
/// Signature (14, self-describing algorithm), the classic RFC 7296 §3.8
/// method 1 (RSA Digital Signature, a bare PKCS#1 v1.5 signature) — a real
/// FortiGate ("Certificates + EAP") sends method 1, not 14, live-confirmed
/// — or the classic RFC 4754 method 9 (ECDSA Digital Signature, a bare
/// raw-`r||s` signature), symmetric with what
/// `crate::ikev2::ike_auth::cert_auth_payload` itself emits under the same
/// circumstances (no negotiated Digital Signature).
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
    // Use: the leaf's key may verify this signature (which also puts a
    // pinned leaf through the extension checks).
    check_signing_key_usage(leaf_der)?;
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
        crate::ikev2::payload::auth_method::ECDSA_SHA256_P256 => vk.verify_ecdsa_p256_raw(auth_data, signed_octets),
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
    fn ecdsa_method9_raw_sign_verify_roundtrips_and_rejects_tampering_and_wrong_key_type() {
        // RFC 4754 classic method 9: no RFC 7427 wrapper, just raw r||s.
        // `crate::ikev2::ike_auth::cert_auth_payload` emits exactly this wire
        // format for an EC key with no negotiated Digital Signature; before
        // this fix, nothing in this module could verify it (audit finding
        // #8, problem 1).
        let signer = ecdsa_leaf_signer();
        let vk = VerifyingKey::from_cert_der(LEAF_CERT_DER).unwrap();
        let octets = b"ResponderSignedOctets under classic method 9";
        let sig = signer.sign_ecdsa_p256_raw(octets).unwrap();
        vk.verify_ecdsa_p256_raw(&sig, octets).unwrap();

        assert!(vk.verify_ecdsa_p256_raw(&sig, b"different octets").is_err());
        let mut bad = sig.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(vk.verify_ecdsa_p256_raw(&bad, octets).is_err());

        // A method-14-wrapped (DER SEQUENCE{r,s}, algorithm-prefixed) signature
        // is not a bare r||s blob and must not verify as one.
        let wrapped = signer.sign_auth_data(octets).unwrap();
        assert!(vk.verify_ecdsa_p256_raw(&wrapped, octets).is_err());

        // An RSA key can never verify an ECDSA signature.
        let (_rsa_signer, rsa_vk) = rsa_signer();
        assert!(rsa_vk.verify_ecdsa_p256_raw(&sig, octets).is_err());
    }

    #[test]
    fn verify_cert_auth_accepts_method_9_symmetrically_with_cert_auth_payload() {
        // Before this fix, `verify_cert_auth` had no branch for method 9 at
        // all, so a peer emitting it -- including this code talking to
        // itself -- could never be verified. Audit finding #8, problem 1.
        let signer = ecdsa_leaf_signer();
        let octets = b"ResponderSignedOctets: msgR | Ni | prf(SK_pr, IDr)";
        let sig = signer.sign_ecdsa_p256_raw(octets).unwrap();
        let now = cert_validity(LEAF_CERT_DER).unwrap().0 + 1;
        verify_cert_auth(
            LEAF_CERT_DER,
            &[],
            &[CA_CERT_DER.to_vec()],
            None,
            now,
            crate::ikev2::payload::auth_method::ECDSA_SHA256_P256,
            &sig,
            octets,
        )
        .unwrap();

        assert!(verify_cert_auth(
            LEAF_CERT_DER,
            &[],
            &[CA_CERT_DER.to_vec()],
            None,
            now,
            crate::ikev2::payload::auth_method::ECDSA_SHA256_P256,
            &sig,
            b"different octets",
        )
        .is_err());
    }

    #[test]
    fn sign_classic_rsa_auth_data_produces_the_prefixed_method1_wire_format() {
        // The RSA counterpart to `sign_ecdsa_p256_raw`'s method 9: what
        // `cert_auth_payload` falls back to for an RSA key with no
        // negotiated Digital Signature. Before this fix that fallback always
        // tried an ECDSA-only operation and simply failed for an RSA key
        // instead of using this valid alternative (audit finding #8, problem 2).
        let (signer, verifier) = rsa_signer();
        let octets = b"InitiatorSignedOctets under classic RSA method 1, via the new helper";
        let sig = signer.sign_classic_rsa_auth_data(octets).unwrap();
        verifier.verify_classic_rsa_auth_data(&sig, octets).unwrap();
        assert!(verifier.verify_classic_rsa_auth_data(&sig, b"tampered").is_err());

        // It's the prefixed method-1 form, not the unprefixed IKEv1 SIG payload.
        assert!(verifier.verify_classic_rsa_raw(&sig, octets).is_err());

        // An ECDSA key cannot produce a method-1 RSA signature.
        let ec_signer = ecdsa_leaf_signer();
        assert!(ec_signer.sign_classic_rsa_auth_data(octets).is_err());
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
        use crate::test_certs::forge::dns;
        use x509_cert::ext::pkix::constraints::name::GeneralSubtree;

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
        assert!(!name_constraints_allow(&excluded, &[dns("vpn.example.com")]));
        assert!(name_constraints_allow(&excluded, &[dns("vpn.other.com")]));

        // Permitted subtree allows only in-domain names.
        let permitted = NameConstraints {
            permitted_subtrees: Some(vec![dns_subtree("example.com")]),
            excluded_subtrees: None,
        };
        assert!(name_constraints_allow(&permitted, &[dns("vpn.example.com")]));
        assert!(!name_constraints_allow(&permitted, &[dns("vpn.other.com")]));

        // A non-dNSName-typed subtree doesn't restrict dNSName matching.
        let other_type = NameConstraints {
            permitted_subtrees: Some(vec![GeneralSubtree {
                base: GeneralName::Rfc822Name(der::asn1::Ia5String::new("user@example.com").unwrap()),
                minimum: 0,
                maximum: None,
            }]),
            excluded_subtrees: None,
        };
        assert!(name_constraints_allow(&other_type, &[dns("vpn.other.com")]));

        // No names at all is vacuously permitted.
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

    // RFC 5280 §4.2 and §6.1 over certificates made at test time by
    // `crate::test_certs::forge`: a root, an intermediate under it and a
    // leaf, each with the extensions a test gives it.
    use crate::test_certs::forge;
    use x509_cert::ext::pkix::KeyUsages;
    use x509_cert::ext::Extension;

    const ROOT: &str = "CN=Forge Root,O=Ryke Test";
    const INT: &str = "CN=Forge Intermediate,O=Ryke Test";
    const LEAF: &str = "CN=vpn.example.com,O=Ryke Test";

    fn root_key() -> SigningKey {
        forge::ec_key(1)
    }
    fn leaf_key() -> SigningKey {
        forge::ec_key(2)
    }
    fn int_key() -> SigningKey {
        forge::ec_key(3)
    }

    fn ca_extensions(path_len: Option<u8>) -> Vec<Extension> {
        vec![forge::basic_constraints(true, path_len), forge::key_usage(KeyUsage(KeyUsages::KeyCertSign | KeyUsages::CRLSign))]
    }

    /// The self-signed root, with `extra` after its CA extensions.
    fn root_with(path_len: Option<u8>, extra: Vec<Extension>) -> Vec<u8> {
        forge::cert(1, ROOT, &root_key(), ROOT, &root_key(), [ca_extensions(path_len), extra].concat())
    }

    /// The intermediate CA under the root, with `extra` after its CA
    /// extensions.
    fn int_with(extra: Vec<Extension>) -> Vec<u8> {
        forge::cert(3, INT, &int_key(), ROOT, &root_key(), [ca_extensions(None), extra].concat())
    }

    /// A leaf for `leaf_key()` under the root, with `extensions` only.
    fn leaf_with(extensions: Vec<Extension>) -> Vec<u8> {
        forge::cert(2, LEAF, &leaf_key(), ROOT, &root_key(), extensions)
    }

    /// A leaf for `leaf_key()` under the intermediate, with no extensions.
    fn leaf_below_int() -> Vec<u8> {
        forge::cert(2, LEAF, &leaf_key(), INT, &int_key(), vec![])
    }

    fn signing_key_usage() -> Extension {
        forge::key_usage(KeyUsage(KeyUsages::DigitalSignature.into()))
    }

    /// `verify_cert_auth` of an AUTH (method 14) made with `leaf_key()`, at
    /// `forge::NOW` and with no name expected.
    fn cert_auth(leaf: &[u8], intermediates: &[Vec<u8>], trusted: &[Vec<u8>]) -> Result<(), IkeError> {
        let octets = b"InitiatorSignedOctets";
        let auth = leaf_key().sign_auth_data(octets).unwrap();
        let method = crate::ikev2::payload::auth_method::DIGITAL_SIGNATURE;
        verify_cert_auth(leaf, intermediates, trusted, None, forge::NOW, method, &auth, octets)
    }

    /// `cert_auth` of a leaf trusted each way: through the root, and pinned.
    fn chained_and_pinned(leaf: &[u8]) -> [Result<(), IkeError>; 2] {
        [cert_auth(leaf, &[], &[root_with(None, vec![])]), cert_auth(leaf, &[], &[leaf.to_vec()])]
    }

    #[test]
    fn cert_auth_refuses_a_leaf_whose_key_usage_forbids_signing() {
        // RFC 4945 §5.1.3.2: if KeyUsage is present, digitalSignature or
        // nonRepudiation "MUST be set" for the key to authenticate IKE.
        let only = |usage: KeyUsages| leaf_with(vec![forge::key_usage(KeyUsage(usage.into()))]);
        for usage in [KeyUsages::KeyEncipherment, KeyUsages::KeyAgreement, KeyUsages::KeyCertSign] {
            let leaf = only(usage);
            assert_eq!(check_signing_key_usage(&leaf), Err(IkeError::AuthFailed), "{usage:?}");
            for result in chained_and_pinned(&leaf) {
                assert_eq!(result, Err(IkeError::AuthFailed), "{usage:?}");
            }
        }
        // Either bit is enough, alone or among others, and a leaf without
        // KeyUsage may sign.
        let both = leaf_with(vec![forge::key_usage(KeyUsage(KeyUsages::DigitalSignature | KeyUsages::KeyEncipherment))]);
        for leaf in [only(KeyUsages::DigitalSignature), only(KeyUsages::NonRepudiation), both, leaf_with(vec![])] {
            check_signing_key_usage(&leaf).unwrap();
            for result in chained_and_pinned(&leaf) {
                result.unwrap();
            }
        }
    }

    /// Extensions this crate does not process: a private one,
    /// ExtendedKeyUsage (serverAuth; RFC 4945 §5.1.3.12 does not require
    /// IKE to support it) and certificatePolicies (anyPolicy; no policy
    /// processing here).
    fn unprocessed_extensions(critical: bool) -> [Extension; 3] {
        [
            forge::raw_ext("1.3.6.1.4.1.55555.123", critical, &[0x05, 0x00]),
            forge::raw_ext("2.5.29.37", critical, &[0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01]),
            forge::raw_ext("2.5.29.32", critical, &[0x30, 0x08, 0x30, 0x06, 0x06, 0x04, 0x55, 0x1d, 0x20, 0x00]),
        ]
    }

    #[test]
    fn certificates_with_a_critical_extension_this_crate_does_not_process_are_refused() {
        // RFC 5280 §4.2: "A certificate-using system MUST reject the
        // certificate if it encounters a critical extension it does not
        // recognize or a critical extension that contains information that
        // it cannot process" -- on the leaf, chained or pinned, on an
        // intermediate, and on the anchor ending the path.
        let root = root_with(None, vec![]);
        for ext in unprocessed_extensions(true) {
            let oid = ext.extn_id;
            for result in chained_and_pinned(&leaf_with(vec![signing_key_usage(), ext.clone()])) {
                assert!(result.is_err(), "leaf {oid}");
            }
            assert!(cert_auth(&leaf_below_int(), &[int_with(vec![ext.clone()])], std::slice::from_ref(&root)).is_err(), "intermediate {oid}");
            assert!(cert_auth(&leaf_with(vec![]), &[], &[root_with(None, vec![ext])]).is_err(), "anchor {oid}");
        }
        // Not critical, the same extensions are passed over wherever they are.
        for ext in unprocessed_extensions(false) {
            for result in chained_and_pinned(&leaf_with(vec![signing_key_usage(), ext.clone()])) {
                result.unwrap();
            }
            cert_auth(&leaf_below_int(), &[int_with(vec![ext.clone()])], std::slice::from_ref(&root)).unwrap();
            cert_auth(&leaf_with(vec![]), &[], &[root_with(None, vec![ext])]).unwrap();
        }
    }

    #[test]
    fn certificates_repeating_an_extension_are_refused() {
        // RFC 5280 §4.2: "A certificate MUST NOT include more than one
        // instance of a particular extension." Which instance counts would
        // be a guess: an intermediate saying CA:TRUE and CA:FALSE, a leaf
        // with two SubjectAltNames, a root with two KeyUsages.
        let san = forge::subject_alt_name(&[forge::dns("vpn.example.com")]);
        let two_sans = leaf_with(vec![san.clone(), san.clone()]);
        for result in chained_and_pinned(&two_sans) {
            assert!(result.is_err());
        }
        assert!(cert_has_dns_name(&two_sans, "vpn.example.com").is_err());
        let private = forge::raw_ext("1.3.6.1.4.1.55555.123", false, &[0x05, 0x00]);
        for result in chained_and_pinned(&leaf_with(vec![private.clone(), private])) {
            assert!(result.is_err());
        }
        let root = root_with(None, vec![]);
        let ca_and_not =
            forge::cert(3, INT, &int_key(), ROOT, &root_key(), vec![forge::basic_constraints(true, None), forge::basic_constraints(false, None)]);
        assert!(cert_auth(&leaf_below_int(), &[ca_and_not], std::slice::from_ref(&root)).is_err());
        let key_cert_sign = forge::key_usage(KeyUsage(KeyUsages::KeyCertSign.into()));
        let two_key_usages =
            forge::cert(1, ROOT, &root_key(), ROOT, &root_key(), vec![forge::basic_constraints(true, None), key_cert_sign.clone(), key_cert_sign]);
        assert!(cert_auth(&leaf_with(vec![]), &[], &[two_key_usages]).is_err());
        // Controls: each once.
        for result in chained_and_pinned(&leaf_with(vec![san])) {
            result.unwrap();
        }
        let ca = forge::cert(3, INT, &int_key(), ROOT, &root_key(), vec![forge::basic_constraints(true, None)]);
        cert_auth(&leaf_below_int(), &[ca], &[root]).unwrap();
    }

    #[test]
    fn extensions_this_crate_reads_must_decode_even_when_not_critical() {
        // RFC 5280 §4.2: a recognized non-critical extension "MUST be
        // processed", so one that does not decode cannot be passed over: a
        // KeyUsage holding an OCTET STRING, a BasicConstraints cut short, a
        // SubjectAltName holding an INTEGER.
        let malformed = [
            forge::raw_ext("2.5.29.15", false, &[0x04, 0x00]),
            forge::raw_ext("2.5.29.19", false, &[0x30, 0x03, 0x01, 0x01]),
            forge::raw_ext("2.5.29.17", false, &[0x02, 0x01, 0x00]),
        ];
        for ext in malformed {
            let oid = ext.extn_id;
            for result in chained_and_pinned(&leaf_with(vec![ext])) {
                assert!(result.is_err(), "{oid}");
            }
        }
    }

    /// `cert_auth` of a leaf for `subject`, with `names` as its
    /// SubjectAltName (none when empty), under a root with `constraints`.
    fn constrained(constraints: Extension, subject: &str, names: &[GeneralName]) -> Result<(), IkeError> {
        let root = root_with(None, vec![constraints]);
        let extensions = if names.is_empty() { vec![] } else { vec![forge::subject_alt_name(names)] };
        cert_auth(&forge::cert(2, subject, &leaf_key(), ROOT, &root_key(), extensions), &[], &[root])
    }

    #[test]
    fn name_constraints_hold_for_the_intermediates_below_too() {
        // RFC 5280 §6.1.3(b): an issuer's constraints hold for every
        // certificate below it, not only the leaf. Here an intermediate's
        // excluded subtree and the SubjectAltName of the CA under it.
        use forge::{dns, name_constraints};
        const SUB: &str = "CN=Forge Sub CA,O=Ryke Test";
        let sub_key = forge::ec_key(4);
        let root = root_with(None, vec![]);
        let int = |excluded| int_with(vec![name_constraints(&[], &[dns(excluded)])]);
        let sub = |name| forge::cert(4, SUB, &sub_key, INT, &int_key(), [ca_extensions(None), vec![forge::subject_alt_name(&[dns(name)])]].concat());
        let leaf = forge::cert(2, LEAF, &leaf_key(), SUB, &sub_key, vec![forge::subject_alt_name(&[dns("vpn.example.com")])]);
        assert!(cert_auth(&leaf, &[sub("ca.evil.test"), int("evil.test")], std::slice::from_ref(&root)).is_err());
        cert_auth(&leaf, &[sub("ca.good.test"), int("evil.test")], std::slice::from_ref(&root)).unwrap();
        // The leaf is held too, as before.
        assert!(cert_auth(&leaf, &[sub("ca.good.test"), int("example.com")], &[root]).is_err());
    }

    #[test]
    fn name_constraints_hold_for_directory_names() {
        // RFC 5280 §4.2.1.10: directoryName constraints hold for a non-empty
        // subject and for directoryNames in the SubjectAltName.
        use forge::{directory, dns, name_constraints};
        let permitted = || name_constraints(&[directory("O=Good")], &[]);
        assert!(constrained(permitted(), "CN=vpn.example.com,O=Evil", &[]).is_err());
        assert!(constrained(permitted(), "CN=vpn.example.com,O=Good", &[directory("CN=x,O=Evil")]).is_err());
        constrained(permitted(), "CN=vpn.example.com,O=Good", &[]).unwrap();
        // RFC 5280 §7.1 via RFC 4518: case does not count.
        constrained(permitted(), "CN=vpn.example.com,O=GOOD", &[directory("CN=x,O=good")]).unwrap();
        let excluded = || name_constraints(&[], &[directory("O=Evil")]);
        assert!(constrained(excluded(), "CN=vpn.example.com,O=Evil", &[]).is_err());
        constrained(excluded(), "CN=vpn.example.com,O=Good", &[]).unwrap();
        // An empty subject is not held.
        let san = vec![forge::subject_alt_name(&[dns("vpn.example.com")])];
        let no_subject = forge::cert_with_names(2, Default::default(), &leaf_key(), ROOT.parse().unwrap(), &root_key(), san);
        cert_auth(&no_subject, &[], &[root_with(None, vec![permitted()])]).unwrap();
    }

    #[test]
    fn name_constraints_hold_for_ip_addresses() {
        // RFC 5280 §4.2.1.10: an iPAddress subtree is an address and mask.
        use forge::{ip, name_constraints};
        let ten = [10, 0, 0, 0, 255, 0, 0, 0];
        assert!(constrained(name_constraints(&[], &[ip(&ten)]), LEAF, &[ip(&[10, 1, 2, 3])]).is_err());
        constrained(name_constraints(&[], &[ip(&ten)]), LEAF, &[ip(&[192, 0, 2, 1])]).unwrap();
        let documentation = [192, 0, 2, 0, 255, 255, 255, 0];
        let v6 = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        assert!(constrained(name_constraints(&[ip(&documentation)], &[]), LEAF, &[ip(&[198, 51, 100, 1])]).is_err());
        // A permitted IPv4 subtree leaves no IPv6 address within.
        assert!(constrained(name_constraints(&[ip(&documentation)], &[]), LEAF, &[ip(&v6)]).is_err());
        constrained(name_constraints(&[ip(&documentation)], &[]), LEAF, &[ip(&[192, 0, 2, 7])]).unwrap();
        // An address of neither length cannot be placed.
        assert!(constrained(name_constraints(&[], &[ip(&ten)]), LEAF, &[ip(&[10, 1, 2])]).is_err());
    }

    #[test]
    fn name_constraints_hold_for_mailboxes_and_subject_email_addresses() {
        use forge::{dns, email, name_constraints};
        let domain = || name_constraints(&[], &[email(".evil.test")]);
        assert!(constrained(domain(), LEAF, &[email("a@mail.evil.test")]).is_err());
        constrained(domain(), LEAF, &[email("a@mail.good.test")]).unwrap();
        // RFC 5280 §4.2.1.10: an rfc822Name constraint holds for the
        // subject's emailAddress attributes when there is no SubjectAltName
        // -- and here also when there is one, the stricter reading.
        fn with_email(mailbox: &str) -> x509_cert::name::Name {
            use x509_cert::attr::AttributeTypeAndValue;
            let mut name: x509_cert::name::Name = LEAF.parse().unwrap();
            let value = der::Any::encode_from(&der::asn1::Ia5String::new(mailbox).unwrap()).unwrap();
            let email = AttributeTypeAndValue { oid: OID_EMAIL_ADDRESS, value };
            name.0.push(x509_cert::name::RelativeDistinguishedName(der::asn1::SetOfVec::try_from(vec![email]).unwrap()));
            name
        }
        let root = root_with(None, vec![name_constraints(&[], &[email("evil.test")])]);
        let leaf = |mailbox, extensions| forge::cert_with_names(2, with_email(mailbox), &leaf_key(), ROOT.parse().unwrap(), &root_key(), extensions);
        assert!(cert_auth(&leaf("a@evil.test", vec![]), &[], std::slice::from_ref(&root)).is_err());
        let san = forge::subject_alt_name(&[dns("vpn.example.com")]);
        assert!(cert_auth(&leaf("a@evil.test", vec![san.clone()]), &[], std::slice::from_ref(&root)).is_err());
        cert_auth(&leaf("a@good.test", vec![]), &[], std::slice::from_ref(&root)).unwrap();
        cert_auth(&leaf("a@good.test", vec![san]), &[], &[root]).unwrap();
    }

    #[test]
    fn mailbox_subtrees_take_the_three_rfc_5280_forms() {
        // RFC 5280 §4.2.1.10: one mailbox, every mailbox at one host, or
        // every mailbox in a domain; the host ignores case, the local part
        // does not (§7.5).
        assert_eq!(mailbox_within("a@evil.test", "evil.test"), Within::Yes);
        assert_eq!(mailbox_within("a@Evil.Test", "evil.test"), Within::Yes);
        assert_eq!(mailbox_within("a@mail.evil.test", "evil.test"), Within::No);
        assert_eq!(mailbox_within("a@mail.evil.test", ".evil.test"), Within::Yes);
        assert_eq!(mailbox_within("a@evil.test", ".evil.test"), Within::No);
        assert_eq!(mailbox_within("a@evil.test", "a@EVIL.test"), Within::Yes);
        assert_eq!(mailbox_within("A@evil.test", "a@evil.test"), Within::No);
        assert_eq!(mailbox_within("evil.test", "evil.test"), Within::Unknown);
    }

    #[test]
    fn attribute_values_match_ignoring_case_and_spaces_across_string_types() {
        use der::{Any, Tag};
        let value = |tag, text: &str| Any::new(tag, text.as_bytes()).unwrap();
        assert!(attribute_values_match(&value(Tag::PrintableString, "Good  Corp"), &value(Tag::Utf8String, " good corp ")));
        assert!(!attribute_values_match(&value(Tag::PrintableString, "Good Corp"), &value(Tag::Utf8String, "GoodCorp")));
        // Other types match only as the same bytes (RFC 5280 §7.1).
        assert!(attribute_values_match(&value(Tag::OctetString, "Good"), &value(Tag::OctetString, "Good")));
        assert!(!attribute_values_match(&value(Tag::OctetString, "Good"), &value(Tag::OctetString, "good")));
    }

    #[test]
    fn name_constraints_of_a_form_this_crate_does_not_process_refuse_names_of_that_form() {
        // RFC 5280 §4.2.1.10: for a constrained name form that appears
        // below, "the application MUST either process the constraint or
        // reject the certificate". uniformResourceIdentifier subtrees are
        // not processed here.
        use forge::{dns, name_constraints, uri};
        let names = |extra: &[GeneralName]| [&[dns("vpn.example.com")][..], extra].concat();
        for constraints in [name_constraints(&[uri(".example.com")], &[]), name_constraints(&[], &[uri(".evil.test")])] {
            assert!(constrained(constraints.clone(), LEAF, &names(&[uri("https://vpn.example.com/")])).is_err());
            // A certificate with no name of that form is not concerned.
            constrained(constraints, LEAF, &names(&[])).unwrap();
        }
    }

    #[test]
    fn name_constraints_with_a_minimum_or_a_maximum_are_refused() {
        // RFC 5280 §4.2.1.10: "the minimum MUST be zero, and maximum MUST be
        // absent".
        use x509_cert::ext::pkix::constraints::name::GeneralSubtree;
        for (minimum, maximum) in [(1, None), (0, Some(3))] {
            let subtree = GeneralSubtree { base: forge::dns("example.com"), minimum, maximum };
            let nc = NameConstraints { permitted_subtrees: Some(vec![subtree]), excluded_subtrees: None };
            let ext = forge::raw_ext("2.5.29.30", true, &der::Encode::to_der(&nc).unwrap());
            assert!(constrained(ext, LEAF, &[forge::dns("vpn.example.com")]).is_err(), "{minimum} {maximum:?}");
        }
        constrained(forge::name_constraints(&[forge::dns("example.com")], &[]), LEAF, &[forge::dns("vpn.example.com")]).unwrap();
    }

    #[test]
    fn path_len_constraint_does_not_count_self_issued_intermediates() {
        // RFC 5280 §4.2.1.9 and §6.1.4(l): pathLenConstraint counts the
        // non-self-issued intermediates. A self-issued one -- the root's
        // own name over a new key, as in a key rollover -- does not.
        let rollover_key = forge::ec_key(5);
        let rollover = forge::cert(5, ROOT, &rollover_key, ROOT, &root_key(), ca_extensions(None));
        let leaf = forge::cert(2, LEAF, &leaf_key(), ROOT, &rollover_key, vec![]);
        cert_auth(&leaf, std::slice::from_ref(&rollover), &[root_with(Some(0), vec![])]).unwrap();
        // A non-self-issued one still counts, above the self-issued one too.
        const SUB: &str = "CN=Forge Sub CA,O=Ryke Test";
        let sub_key = forge::ec_key(6);
        let sub = forge::cert(6, SUB, &sub_key, ROOT, &rollover_key, ca_extensions(None));
        let below_sub = forge::cert(2, LEAF, &leaf_key(), SUB, &sub_key, vec![]);
        assert!(cert_auth(&below_sub, &[sub.clone(), rollover.clone()], &[root_with(Some(0), vec![])]).is_err());
        cert_auth(&below_sub, &[sub, rollover], &[root_with(Some(1), vec![])]).unwrap();
    }

    #[test]
    fn a_self_issued_intermediate_is_not_held_to_its_issuers_name_constraints() {
        // RFC 5280 §6.1.3(b): "If certificate i is self-issued and it is not
        // the final certificate in the path, skip this step for certificate
        // i." The root permits only O=Other below it, but its rollover
        // certificate carries the root's own name.
        let root = root_with(None, vec![forge::name_constraints(&[forge::directory("O=Other")], &[])]);
        let rollover_key = forge::ec_key(5);
        let rollover = forge::cert(5, ROOT, &rollover_key, ROOT, &root_key(), ca_extensions(None));
        let leaf = |subject| forge::cert(2, subject, &leaf_key(), ROOT, &rollover_key, vec![]);
        cert_auth(&leaf("CN=vpn.example.com,O=Other"), std::slice::from_ref(&rollover), std::slice::from_ref(&root)).unwrap();
        // The leaf is still held.
        assert!(cert_auth(&leaf(LEAF), &[rollover], &[root]).is_err());
    }

    #[test]
    fn path_len_constraint_holds_past_255_intermediates() {
        // The count of intermediates must not wrap: 256 of them under a
        // root allowing none.
        let key = forge::ec_key(7);
        let subject = |i: usize| format!("CN=Forge CA {i},O=Ryke Test");
        let mut intermediates = vec![forge::cert(1000, &subject(0), &key, ROOT, &root_key(), ca_extensions(None))];
        for i in 1..256 {
            intermediates.push(forge::cert(1000 + i as u32, &subject(i), &key, &subject(i - 1), &key, ca_extensions(None)));
        }
        let leaf = forge::cert(2, LEAF, &leaf_key(), &subject(255), &key, vec![]);
        assert!(cert_auth(&leaf, &intermediates, &[root_with(Some(0), vec![])]).is_err());
        cert_auth(&leaf, &intermediates, &[root_with(None, vec![])]).unwrap();
    }
}
