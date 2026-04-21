use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ecdsa::signature::Verifier;
use jsonwebtoken::jwk::Jwk;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, crypto};
use k256::ecdsa::{
    Signature as K256Signature, SigningKey as K256SigningKey, VerifyingKey as K256VerifyingKey,
};
use k256::SecretKey as K256SecretKey;
use openssl::bn::BigNum;
use openssl::ec::EcKey;
use openssl::ecdsa::EcdsaSig;
use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{HasParams, Id as PKeyId, PKey, Private, Public};
use openssl::rsa::Padding;
use openssl::sign::{RsaPssSaltlen, Signer as OpenSslSigner, Verifier as OpenSslVerifier};
use p521::ecdsa::{
    Signature as P521Signature, SigningKey as P521SigningKey, VerifyingKey as P521VerifyingKey,
};
use pyo3::exceptions::PyTypeError;
use pyo3::prelude::*;
use pyo3::types::PyAny;
use pyo3::{Bound, create_exception};
use serde_json::Value;
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::sync::atomic::{AtomicU64, Ordering};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

create_exception!(_rust_pyjwt, RustJWTError, pyo3::exceptions::PyException);
create_exception!(_rust_pyjwt, RustInvalidKeyError, RustJWTError);
create_exception!(_rust_pyjwt, RustInvalidAlgorithmError, RustJWTError);

fn invalid_key_err(message: impl Into<String>) -> PyErr {
    RustInvalidKeyError::new_err(message.into())
}

fn invalid_algorithm_err(message: impl Into<String>) -> PyErr {
    RustInvalidAlgorithmError::new_err(message.into())
}

fn jwt_err(message: impl Into<String>) -> PyErr {
    RustJWTError::new_err(message.into())
}

#[derive(Hash, Eq, PartialEq, Clone)]
enum CacheUsage {
    Encode,
    Decode,
}

#[derive(Hash, Eq, PartialEq, Clone)]
struct CacheKey {
    algorithm: &'static str,
    usage: CacheUsage,
    key_bytes: Vec<u8>,
}

static ENCODING_KEY_CACHE: OnceLock<Mutex<HashMap<CacheKey, EncodingKey>>> = OnceLock::new();
static DECODING_KEY_CACHE: OnceLock<Mutex<HashMap<CacheKey, DecodingKey>>> = OnceLock::new();
static HANDLE_ID_SEQ: AtomicU64 = AtomicU64::new(1);
static HANDLE_REGISTRY: OnceLock<Mutex<HashMap<u64, Arc<StoredKey>>>> = OnceLock::new();
static HANDLE_CACHE: OnceLock<Mutex<HashMap<CacheKey, u64>>> = OnceLock::new();

#[pyclass(module = "jwt_rs._rust_pyjwt", frozen, from_py_object)]
#[derive(Clone)]
struct RustKeyHandle {
    #[pyo3(get)]
    id: u64,
    #[pyo3(get)]
    algorithm: String,
    #[pyo3(get)]
    usage: String,
}

#[derive(Clone)]
enum StoredKey {
    Encoding(EncodingKey),
    Decoding(DecodingKey),
    RsaPrivate(PKey<Private>),
    RsaPublic(PKey<Public>),
    EcPrivate(EcKey<Private>, usize),
    EcPublic(EcKey<Public>, usize),
    EdPrivate(PKey<Private>),
    EdPublic(PKey<Public>),
}

fn extract_key_bytes(key: &Bound<'_, PyAny>) -> PyResult<Vec<u8>> {
    if key.is_none() {
        return Ok(Vec::new());
    }
    if let Ok(text) = key.extract::<String>() {
        return Ok(text.into_bytes());
    }
    if let Ok(bytes) = key.extract::<Vec<u8>>() {
        return Ok(bytes);
    }
    Err(PyTypeError::new_err("key must be str, bytes, or None"))
}

fn extract_bytes_or_string(value: &Bound<'_, PyAny>, arg_name: &str) -> PyResult<Vec<u8>> {
    if let Ok(bytes) = value.extract::<Vec<u8>>() {
        return Ok(bytes);
    }
    if let Ok(text) = value.extract::<String>() {
        return Ok(text.into_bytes());
    }
    Err(PyTypeError::new_err(format!(
        "argument '{arg_name}': must be str or bytes"
    )))
}

fn parse_algorithm(name: &str) -> PyResult<Algorithm> {
    match name {
        "HS256" => Ok(Algorithm::HS256),
        "HS384" => Ok(Algorithm::HS384),
        "HS512" => Ok(Algorithm::HS512),
        "RS256" => Ok(Algorithm::RS256),
        "RS384" => Ok(Algorithm::RS384),
        "RS512" => Ok(Algorithm::RS512),
        "PS256" => Ok(Algorithm::PS256),
        "PS384" => Ok(Algorithm::PS384),
        "PS512" => Ok(Algorithm::PS512),
        "ES256" => Ok(Algorithm::ES256),
        "ES384" => Ok(Algorithm::ES384),
        "EdDSA" => Ok(Algorithm::EdDSA),
        other => Err(invalid_algorithm_err(format!(
            "unsupported algorithm: {other}"
        ))),
    }
}

fn encoding_key_cache() -> &'static Mutex<HashMap<CacheKey, EncodingKey>> {
    ENCODING_KEY_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn decoding_key_cache() -> &'static Mutex<HashMap<CacheKey, DecodingKey>> {
    DECODING_KEY_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn handle_registry() -> &'static Mutex<HashMap<u64, Arc<StoredKey>>> {
    HANDLE_REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

fn handle_cache() -> &'static Mutex<HashMap<CacheKey, u64>> {
    HANDLE_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn cached_encoding_key(
    algorithm_name: &'static str,
    key_bytes: &[u8],
    build: impl FnOnce() -> PyResult<EncodingKey>,
) -> PyResult<EncodingKey> {
    let cache_key = CacheKey {
        algorithm: algorithm_name,
        usage: CacheUsage::Encode,
        key_bytes: key_bytes.to_vec(),
    };
    if let Some(cached) = encoding_key_cache()
        .lock()
        .map_err(|_| jwt_err("encoding key cache poisoned"))?
        .get(&cache_key)
        .cloned()
    {
        return Ok(cached);
    }
    let key = build()?;
    encoding_key_cache()
        .lock()
        .map_err(|_| jwt_err("encoding key cache poisoned"))?
        .insert(cache_key, key.clone());
    Ok(key)
}

fn cached_decoding_key(
    algorithm_name: &'static str,
    key_bytes: &[u8],
    build: impl FnOnce() -> PyResult<DecodingKey>,
) -> PyResult<DecodingKey> {
    let cache_key = CacheKey {
        algorithm: algorithm_name,
        usage: CacheUsage::Decode,
        key_bytes: key_bytes.to_vec(),
    };
    if let Some(cached) = decoding_key_cache()
        .lock()
        .map_err(|_| jwt_err("decoding key cache poisoned"))?
        .get(&cache_key)
        .cloned()
    {
        return Ok(cached);
    }
    let key = build()?;
    decoding_key_cache()
        .lock()
        .map_err(|_| jwt_err("decoding key cache poisoned"))?
        .insert(cache_key, key.clone());
    Ok(key)
}

fn openssl_key_err(err: ErrorStack) -> PyErr {
    invalid_key_err(err.to_string())
}

fn openssl_jwt_err(err: ErrorStack) -> PyErr {
    jwt_err(err.to_string())
}

fn is_rsa_algorithm(algorithm: &str) -> bool {
    matches!(
        algorithm,
        "RS256" | "RS384" | "RS512" | "PS256" | "PS384" | "PS512"
    )
}

fn is_ec_algorithm(algorithm: &str) -> bool {
    matches!(
        algorithm,
        "ES256" | "ES384" | "ES512" | "ES521" | "ES256K"
    )
}

fn message_digest_for_algorithm(algorithm: &str) -> PyResult<MessageDigest> {
    match algorithm {
        "RS256" | "PS256" | "ES256" | "ES256K" => Ok(MessageDigest::sha256()),
        "RS384" | "PS384" | "ES384" => Ok(MessageDigest::sha384()),
        "RS512" | "PS512" | "ES512" | "ES521" => Ok(MessageDigest::sha512()),
        other => Err(invalid_algorithm_err(format!(
            "unsupported digest algorithm: {other}"
        ))),
    }
}

fn ec_curve_info(algorithm: &str) -> PyResult<(Nid, usize)> {
    match algorithm {
        "ES256" => Ok((Nid::X9_62_PRIME256V1, 32)),
        "ES384" => Ok((Nid::SECP384R1, 48)),
        "ES512" | "ES521" => Ok((Nid::SECP521R1, 66)),
        "ES256K" => Ok((Nid::SECP256K1, 32)),
        other => Err(invalid_algorithm_err(format!(
            "unsupported EC algorithm: {other}"
        ))),
    }
}

fn ensure_ec_curve<T>(key: &openssl::ec::EcKeyRef<T>, algorithm: &str) -> PyResult<usize>
where
    T: HasParams,
{
    let (expected_curve, coordinate_size) = ec_curve_info(algorithm)?;
    let actual_curve = key
        .group()
        .curve_name()
        .ok_or_else(|| invalid_key_err("EC key is missing a named curve"))?;
    if actual_curve != expected_curve {
        return Err(invalid_key_err(format!(
            "EC key curve does not match algorithm {algorithm}"
        )));
    }
    Ok(coordinate_size)
}

fn parse_rsa_private_key(key_bytes: &[u8]) -> PyResult<PKey<Private>> {
    let key = PKey::private_key_from_pem(key_bytes).map_err(openssl_key_err)?;
    if key.id() != PKeyId::RSA {
        return Err(invalid_key_err("Expected an RSA private key"));
    }
    Ok(key)
}

fn normalize_algorithm_name(algorithm: &str) -> PyResult<&'static str> {
    match algorithm {
        "HS256" => Ok("HS256"),
        "HS384" => Ok("HS384"),
        "HS512" => Ok("HS512"),
        "RS256" => Ok("RS256"),
        "RS384" => Ok("RS384"),
        "RS512" => Ok("RS512"),
        "PS256" => Ok("PS256"),
        "PS384" => Ok("PS384"),
        "PS512" => Ok("PS512"),
        "ES256" => Ok("ES256"),
        "ES384" => Ok("ES384"),
        "ES512" => Ok("ES512"),
        "ES521" => Ok("ES521"),
        "ES256K" => Ok("ES256K"),
        "EdDSA" => Ok("EdDSA"),
        "none" => Ok("none"),
        _ => Err(invalid_algorithm_err(format!("unsupported algorithm: {algorithm}"))),
    }
}

fn parse_rsa_public_or_private_for_verify(key_bytes: &[u8]) -> PyResult<StoredKey> {
    if let Ok(key) = PKey::public_key_from_pem(key_bytes) {
        if key.id() == PKeyId::RSA {
            return Ok(StoredKey::RsaPublic(key));
        }
    }
    Ok(StoredKey::RsaPrivate(parse_rsa_private_key(key_bytes)?))
}

fn parse_ec_private_key(key_bytes: &[u8], algorithm: &str) -> PyResult<(EcKey<Private>, usize)> {
    let key = PKey::private_key_from_pem(key_bytes).map_err(openssl_key_err)?;
    let ec_key = key.ec_key().map_err(openssl_key_err)?;
    let coordinate_size = ensure_ec_curve(ec_key.as_ref(), algorithm)?;
    Ok((ec_key, coordinate_size))
}

fn parse_ec_public_or_private_for_verify(
    key_bytes: &[u8],
    algorithm: &str,
) -> PyResult<StoredKey> {
    if let Ok(key) = PKey::public_key_from_pem(key_bytes) {
        let ec_key = key.ec_key().map_err(openssl_key_err)?;
        let coordinate_size = ensure_ec_curve(ec_key.as_ref(), algorithm)?;
        return Ok(StoredKey::EcPublic(ec_key, coordinate_size));
    }
    let (ec_key, coordinate_size) = parse_ec_private_key(key_bytes, algorithm)?;
    Ok(StoredKey::EcPrivate(ec_key, coordinate_size))
}

fn parse_ed_private_key(key_bytes: &[u8]) -> PyResult<PKey<Private>> {
    PKey::private_key_from_pem(key_bytes).map_err(openssl_key_err)
}

fn parse_ed_public_or_private_for_verify(key_bytes: &[u8]) -> PyResult<StoredKey> {
    if let Ok(key) = PKey::public_key_from_pem(key_bytes) {
        return Ok(StoredKey::EdPublic(key));
    }
    Ok(StoredKey::EdPrivate(parse_ed_private_key(key_bytes)?))
}

fn pad_signature_component(component: &openssl::bn::BigNumRef, coordinate_size: usize) -> PyResult<Vec<u8>> {
    let bytes = component.to_vec();
    if bytes.len() > coordinate_size {
        return Err(jwt_err("ECDSA signature component is larger than expected"));
    }
    let mut padded = vec![0_u8; coordinate_size - bytes.len()];
    padded.extend_from_slice(&bytes);
    Ok(padded)
}

fn raw_jwt_signature_to_ecdsa_sig(signature: &str, coordinate_size: usize) -> PyResult<EcdsaSig> {
    let raw = URL_SAFE_NO_PAD
        .decode(signature)
        .map_err(|err| jwt_err(err.to_string()))?;
    if raw.len() != coordinate_size * 2 {
        return Err(jwt_err("Invalid ECDSA signature length"));
    }
    let r = BigNum::from_slice(&raw[..coordinate_size]).map_err(openssl_jwt_err)?;
    let s = BigNum::from_slice(&raw[coordinate_size..]).map_err(openssl_jwt_err)?;
    EcdsaSig::from_private_components(r, s).map_err(openssl_jwt_err)
}

fn sign_with_rsa(message: &[u8], key: &PKey<Private>, algorithm: &str) -> PyResult<String> {
    let digest = message_digest_for_algorithm(algorithm)?;
    let mut signer = OpenSslSigner::new(digest, key).map_err(openssl_jwt_err)?;
    if algorithm.starts_with("PS") {
        signer
            .set_rsa_padding(Padding::PKCS1_PSS)
            .map_err(openssl_jwt_err)?;
        signer.set_rsa_mgf1_md(digest).map_err(openssl_jwt_err)?;
        signer
            .set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)
            .map_err(openssl_jwt_err)?;
    } else {
        signer
            .set_rsa_padding(Padding::PKCS1)
            .map_err(openssl_jwt_err)?;
    }
    signer.update(message).map_err(openssl_jwt_err)?;
    let signature = signer.sign_to_vec().map_err(openssl_jwt_err)?;
    Ok(URL_SAFE_NO_PAD.encode(signature))
}

fn verify_with_rsa_public(
    signature: &str,
    message: &[u8],
    key: &PKey<Public>,
    algorithm: &str,
) -> PyResult<bool> {
    let digest = message_digest_for_algorithm(algorithm)?;
    let signature = URL_SAFE_NO_PAD
        .decode(signature)
        .map_err(|err| jwt_err(err.to_string()))?;
    let mut verifier = OpenSslVerifier::new(digest, key).map_err(openssl_jwt_err)?;
    if algorithm.starts_with("PS") {
        verifier
            .set_rsa_padding(Padding::PKCS1_PSS)
            .map_err(openssl_jwt_err)?;
        verifier.set_rsa_mgf1_md(digest).map_err(openssl_jwt_err)?;
        verifier
            .set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)
            .map_err(openssl_jwt_err)?;
    } else {
        verifier
            .set_rsa_padding(Padding::PKCS1)
            .map_err(openssl_jwt_err)?;
    }
    verifier.update(message).map_err(openssl_jwt_err)?;
    verifier.verify(&signature).map_err(openssl_jwt_err)
}

fn verify_with_rsa_private(
    signature: &str,
    message: &[u8],
    key: &PKey<Private>,
    algorithm: &str,
) -> PyResult<bool> {
    let digest = message_digest_for_algorithm(algorithm)?;
    let signature = URL_SAFE_NO_PAD
        .decode(signature)
        .map_err(|err| jwt_err(err.to_string()))?;
    let mut verifier = OpenSslVerifier::new(digest, key).map_err(openssl_jwt_err)?;
    if algorithm.starts_with("PS") {
        verifier
            .set_rsa_padding(Padding::PKCS1_PSS)
            .map_err(openssl_jwt_err)?;
        verifier.set_rsa_mgf1_md(digest).map_err(openssl_jwt_err)?;
        verifier
            .set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)
            .map_err(openssl_jwt_err)?;
    } else {
        verifier
            .set_rsa_padding(Padding::PKCS1)
            .map_err(openssl_jwt_err)?;
    }
    verifier.update(message).map_err(openssl_jwt_err)?;
    verifier.verify(&signature).map_err(openssl_jwt_err)
}

fn sign_with_ec(message: &[u8], key: &EcKey<Private>, algorithm: &str, coordinate_size: usize) -> PyResult<String> {
    let digest = compute_digest(message, algorithm)?;
    let signature = EcdsaSig::sign(&digest, key.as_ref()).map_err(openssl_jwt_err)?;
    let mut raw = pad_signature_component(signature.r(), coordinate_size)?;
    raw.extend_from_slice(&pad_signature_component(signature.s(), coordinate_size)?);
    Ok(URL_SAFE_NO_PAD.encode(raw))
}

fn verify_with_ec_public(
    signature: &str,
    message: &[u8],
    key: &EcKey<Public>,
    algorithm: &str,
    coordinate_size: usize,
) -> PyResult<bool> {
    let digest = compute_digest(message, algorithm)?;
    let signature = raw_jwt_signature_to_ecdsa_sig(signature, coordinate_size)?;
    signature.verify(&digest, key.as_ref()).map_err(openssl_jwt_err)
}

fn verify_with_ec_private(
    signature: &str,
    message: &[u8],
    key: &EcKey<Private>,
    algorithm: &str,
    coordinate_size: usize,
) -> PyResult<bool> {
    let digest = compute_digest(message, algorithm)?;
    let signature = raw_jwt_signature_to_ecdsa_sig(signature, coordinate_size)?;
    signature.verify(&digest, key.as_ref()).map_err(openssl_jwt_err)
}

fn sign_with_ed(message: &[u8], key: &PKey<Private>) -> PyResult<String> {
    let mut signer = OpenSslSigner::new_without_digest(key).map_err(openssl_jwt_err)?;
    let signature = signer
        .sign_oneshot_to_vec(message)
        .map_err(openssl_jwt_err)?;
    Ok(URL_SAFE_NO_PAD.encode(signature))
}

fn verify_with_ed_public(signature: &str, message: &[u8], key: &PKey<Public>) -> PyResult<bool> {
    let signature = URL_SAFE_NO_PAD
        .decode(signature)
        .map_err(|err| jwt_err(err.to_string()))?;
    let mut verifier = OpenSslVerifier::new_without_digest(key).map_err(openssl_jwt_err)?;
    verifier
        .verify_oneshot(&signature, message)
        .map_err(openssl_jwt_err)
}

fn verify_with_ed_private(signature: &str, message: &[u8], key: &PKey<Private>) -> PyResult<bool> {
    let signature = URL_SAFE_NO_PAD
        .decode(signature)
        .map_err(|err| jwt_err(err.to_string()))?;
    let mut verifier = OpenSslVerifier::new_without_digest(key).map_err(openssl_jwt_err)?;
    verifier
        .verify_oneshot(&signature, message)
        .map_err(openssl_jwt_err)
}

fn sign_with_stored_key(message: &[u8], stored: &StoredKey, algorithm: &str) -> PyResult<String> {
    match stored {
        StoredKey::Encoding(encoding_key) => {
            let algorithm = parse_algorithm(algorithm)?;
            crypto::sign(message, encoding_key, algorithm).map_err(|err| jwt_err(err.to_string()))
        }
        StoredKey::RsaPrivate(key) => sign_with_rsa(message, key, algorithm),
        StoredKey::EcPrivate(key, coordinate_size) => {
            sign_with_ec(message, key, algorithm, *coordinate_size)
        }
        StoredKey::EdPrivate(key) => sign_with_ed(message, key),
        _ => Err(invalid_key_err("prepared key handle is not valid for signing")),
    }
}

fn verify_with_stored_key(
    signature: &str,
    message: &[u8],
    stored: &StoredKey,
    algorithm: &str,
) -> PyResult<bool> {
    match stored {
        StoredKey::Decoding(decoding_key) => {
            let algorithm = parse_algorithm(algorithm)?;
            crypto::verify(signature, message, decoding_key, algorithm)
                .map_err(|err| jwt_err(err.to_string()))
        }
        StoredKey::RsaPublic(key) => verify_with_rsa_public(signature, message, key, algorithm),
        StoredKey::RsaPrivate(key) => verify_with_rsa_private(signature, message, key, algorithm),
        StoredKey::EcPublic(key, coordinate_size) => {
            verify_with_ec_public(signature, message, key, algorithm, *coordinate_size)
        }
        StoredKey::EcPrivate(key, coordinate_size) => {
            verify_with_ec_private(signature, message, key, algorithm, *coordinate_size)
        }
        StoredKey::EdPublic(key) => verify_with_ed_public(signature, message, key),
        StoredKey::EdPrivate(key) => verify_with_ed_private(signature, message, key),
        _ => Err(invalid_key_err("prepared key handle is not valid for verification")),
    }
}

fn sign_with_stored_key_raw(message: &[u8], stored: &StoredKey, algorithm: &str) -> PyResult<Vec<u8>> {
    let signature = sign_with_stored_key(message, stored, algorithm)?;
    URL_SAFE_NO_PAD
        .decode(signature)
        .map_err(|err| jwt_err(err.to_string()))
}

fn verify_with_stored_key_raw(
    signature: &[u8],
    message: &[u8],
    stored: &StoredKey,
    algorithm: &str,
) -> PyResult<bool> {
    let signature = URL_SAFE_NO_PAD.encode(signature);
    verify_with_stored_key(&signature, message, stored, algorithm)
}

fn put_handle(
    algorithm_name: &'static str,
    usage: CacheUsage,
    key_bytes: &[u8],
    build: impl FnOnce() -> PyResult<StoredKey>,
) -> PyResult<RustKeyHandle> {
    let cache_key = CacheKey {
        algorithm: algorithm_name,
        usage: usage.clone(),
        key_bytes: key_bytes.to_vec(),
    };

    if let Some(id) = handle_cache()
        .lock()
        .map_err(|_| jwt_err("handle cache poisoned"))?
        .get(&cache_key)
        .copied()
    {
        return Ok(RustKeyHandle {
            id,
            algorithm: algorithm_name.to_string(),
            usage: match usage {
                CacheUsage::Encode => "encode".to_string(),
                CacheUsage::Decode => "decode".to_string(),
            },
        });
    }

    let id = HANDLE_ID_SEQ.fetch_add(1, Ordering::Relaxed);
    let stored = Arc::new(build()?);
    handle_registry()
        .lock()
        .map_err(|_| jwt_err("handle registry poisoned"))?
        .insert(id, stored);
    handle_cache()
        .lock()
        .map_err(|_| jwt_err("handle cache poisoned"))?
        .insert(cache_key, id);

    Ok(RustKeyHandle {
        id,
        algorithm: algorithm_name.to_string(),
        usage: match usage {
            CacheUsage::Encode => "encode".to_string(),
            CacheUsage::Decode => "decode".to_string(),
        },
    })
}

fn stored_key_from_handle(handle: &RustKeyHandle) -> PyResult<Arc<StoredKey>> {
    handle_registry()
        .lock()
        .map_err(|_| jwt_err("handle registry poisoned"))?
        .get(&handle.id)
        .cloned()
        .ok_or_else(|| invalid_key_err("unknown prepared key handle"))
}

fn build_stored_key_from_bytes(
    algorithm_name: &'static str,
    usage: &CacheUsage,
    key_bytes: &[u8],
) -> PyResult<StoredKey> {
    match (algorithm_name, usage) {
        ("RS256" | "RS384" | "RS512" | "PS256" | "PS384" | "PS512", CacheUsage::Encode) => {
            Ok(StoredKey::RsaPrivate(parse_rsa_private_key(key_bytes)?))
        }
        ("RS256" | "RS384" | "RS512" | "PS256" | "PS384" | "PS512", CacheUsage::Decode) => {
            parse_rsa_public_or_private_for_verify(key_bytes)
        }
        ("ES256" | "ES384" | "ES512" | "ES521" | "ES256K", CacheUsage::Encode) => {
            let (ec_key, coordinate_size) = parse_ec_private_key(key_bytes, algorithm_name)?;
            Ok(StoredKey::EcPrivate(ec_key, coordinate_size))
        }
        ("ES256" | "ES384" | "ES512" | "ES521" | "ES256K", CacheUsage::Decode) => {
            parse_ec_public_or_private_for_verify(key_bytes, algorithm_name)
        }
        ("EdDSA", CacheUsage::Encode) => Ok(StoredKey::EdPrivate(parse_ed_private_key(key_bytes)?)),
        ("EdDSA", CacheUsage::Decode) => parse_ed_public_or_private_for_verify(key_bytes),
        (_, CacheUsage::Encode) => {
            let alg = parse_algorithm(algorithm_name)?;
            Ok(StoredKey::Encoding(build_encoding_key(alg, key_bytes)?))
        }
        (_, CacheUsage::Decode) => {
            let alg = parse_algorithm(algorithm_name)?;
            Ok(StoredKey::Decoding(build_decoding_key(alg, key_bytes)?))
        }
    }
}

fn build_encoding_key(algorithm: Algorithm, key_bytes: &[u8]) -> PyResult<EncodingKey> {
    match algorithm {
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
            let name = match algorithm {
                Algorithm::HS256 => "HS256",
                Algorithm::HS384 => "HS384",
                _ => "HS512",
            };
            cached_encoding_key(name, key_bytes, || Ok(EncodingKey::from_secret(key_bytes)))
        }
        Algorithm::RS256
        | Algorithm::RS384
        | Algorithm::RS512
        | Algorithm::PS256
        | Algorithm::PS384
        | Algorithm::PS512 => {
            let name = match algorithm {
                Algorithm::RS256 => "RS256",
                Algorithm::RS384 => "RS384",
                Algorithm::RS512 => "RS512",
                Algorithm::PS256 => "PS256",
                Algorithm::PS384 => "PS384",
                _ => "PS512",
            };
            cached_encoding_key(name, key_bytes, || {
                EncodingKey::from_rsa_pem(key_bytes).map_err(|err| invalid_key_err(err.to_string()))
            })
        }
        Algorithm::ES256 | Algorithm::ES384 => {
            let name = if algorithm == Algorithm::ES256 { "ES256" } else { "ES384" };
            cached_encoding_key(name, key_bytes, || {
                EncodingKey::from_ec_pem(key_bytes).map_err(|err| invalid_key_err(err.to_string()))
            })
        }
        Algorithm::EdDSA => {
            cached_encoding_key("EdDSA", key_bytes, || {
                EncodingKey::from_ed_pem(key_bytes).map_err(|err| invalid_key_err(err.to_string()))
            })
        }
    }
}

fn build_decoding_key(algorithm: Algorithm, key_bytes: &[u8]) -> PyResult<DecodingKey> {
    match algorithm {
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
            let name = match algorithm {
                Algorithm::HS256 => "HS256",
                Algorithm::HS384 => "HS384",
                _ => "HS512",
            };
            cached_decoding_key(name, key_bytes, || Ok(DecodingKey::from_secret(key_bytes)))
        }
        Algorithm::RS256
        | Algorithm::RS384
        | Algorithm::RS512
        | Algorithm::PS256
        | Algorithm::PS384
        | Algorithm::PS512 => {
            let name = match algorithm {
                Algorithm::RS256 => "RS256",
                Algorithm::RS384 => "RS384",
                Algorithm::RS512 => "RS512",
                Algorithm::PS256 => "PS256",
                Algorithm::PS384 => "PS384",
                _ => "PS512",
            };
            cached_decoding_key(name, key_bytes, || {
                DecodingKey::from_rsa_pem(key_bytes).map_err(|err| invalid_key_err(err.to_string()))
            })
        }
        Algorithm::ES256 | Algorithm::ES384 => {
            let name = if algorithm == Algorithm::ES256 { "ES256" } else { "ES384" };
            cached_decoding_key(name, key_bytes, || {
                DecodingKey::from_ec_pem(key_bytes).map_err(|err| invalid_key_err(err.to_string()))
            })
        }
        Algorithm::EdDSA => {
            cached_decoding_key("EdDSA", key_bytes, || {
                DecodingKey::from_ed_pem(key_bytes).map_err(|err| invalid_key_err(err.to_string()))
            })
        }
    }
}

fn decode_token_segments(token: &[u8]) -> PyResult<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)> {
    let last_dot = token
        .iter()
        .rposition(|&b| b == b'.')
        .ok_or_else(|| jwt_err("Not enough segments"))?;
    let signing_input = &token[..last_dot];
    let crypto_segment = &token[last_dot + 1..];

    let first_dot = signing_input
        .iter()
        .position(|&b| b == b'.')
        .ok_or_else(|| jwt_err("Not enough segments"))?;
    let header_segment = &signing_input[..first_dot];
    let payload_segment = &signing_input[first_dot + 1..];

    let header_data = URL_SAFE_NO_PAD
        .decode(header_segment)
        .map_err(|_| jwt_err("Invalid header padding"))?;
    let payload = URL_SAFE_NO_PAD
        .decode(payload_segment)
        .map_err(|_| jwt_err("Invalid payload padding"))?;
    let signature = URL_SAFE_NO_PAD
        .decode(crypto_segment)
        .map_err(|_| jwt_err("Invalid crypto padding"))?;

    Ok((payload, signing_input.to_vec(), header_data, signature))
}

fn compute_digest(message: &[u8], algorithm: &str) -> PyResult<Vec<u8>> {
    match algorithm {
        "HS256" | "RS256" | "PS256" | "ES256" | "ES256K" => Ok(Sha256::digest(message).to_vec()),
        "HS384" | "RS384" | "PS384" | "ES384" => Ok(Sha384::digest(message).to_vec()),
        "HS512" | "RS512" | "PS512" | "ES512" | "ES521" => Ok(Sha512::digest(message).to_vec()),
        other => Err(invalid_algorithm_err(format!(
            "unsupported digest algorithm: {other}"
        ))),
    }
}

fn jwk_field<'a>(obj: &'a Value, field: &str) -> PyResult<&'a str> {
    obj.get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_key_err(format!("missing or invalid JWK field: {field}")))
}

fn decode_b64u_field(obj: &Value, field: &str) -> PyResult<Vec<u8>> {
    let value = jwk_field(obj, field)?;
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|err| invalid_key_err(err.to_string()))
}

fn verify_es512_with_jwk(signature: &str, message: &[u8], jwk_json: &str) -> PyResult<bool> {
    let obj: Value = serde_json::from_str(jwk_json).map_err(|err| invalid_key_err(err.to_string()))?;
    if jwk_field(&obj, "kty")? != "EC" {
        return Err(invalid_key_err("Not an EC key"));
    }
    if jwk_field(&obj, "crv")? != "P-521" {
        return Err(invalid_key_err("Invalid curve: expected P-521"));
    }

    let signature_bytes = URL_SAFE_NO_PAD
        .decode(signature)
        .map_err(|err| jwt_err(err.to_string()))?;
    let signature =
        P521Signature::from_slice(&signature_bytes).map_err(|err| jwt_err(err.to_string()))?;

    if obj.get("d").is_some() {
        let d = decode_b64u_field(&obj, "d")?;
        if d.len() > 66 {
            return Err(invalid_key_err("invalid P-521 private key length"));
        }
        let padded = if d.len() < 66 {
            let mut out = vec![0_u8; 66 - d.len()];
            out.extend_from_slice(&d);
            out
        } else {
            d
        };
        let signing_key =
            P521SigningKey::from_slice(&padded).map_err(|err| invalid_key_err(err.to_string()))?;
        let verifying_key = P521VerifyingKey::from(&signing_key);
        return Ok(verifying_key.verify(message, &signature).is_ok());
    }

    let x = decode_b64u_field(&obj, "x")?;
    let y = decode_b64u_field(&obj, "y")?;
    if x.len() > 66 || y.len() > 66 {
        return Err(invalid_key_err("invalid P-521 coordinate length"));
    }
    let mut encoded = Vec::with_capacity(1 + 66 + 66);
    encoded.push(0x04);
    encoded.extend(std::iter::repeat_n(0_u8, 66 - x.len()));
    encoded.extend_from_slice(&x);
    encoded.extend(std::iter::repeat_n(0_u8, 66 - y.len()));
    encoded.extend_from_slice(&y);
    let verifying_key = P521VerifyingKey::from_sec1_bytes(&encoded)
        .map_err(|err| invalid_key_err(err.to_string()))?;
    Ok(verifying_key.verify(message, &signature).is_ok())
}

fn verify_es256k_with_jwk(signature: &str, message: &[u8], jwk_json: &str) -> PyResult<bool> {
    let obj: Value = serde_json::from_str(jwk_json).map_err(|err| invalid_key_err(err.to_string()))?;
    if jwk_field(&obj, "kty")? != "EC" {
        return Err(invalid_key_err("Not an EC key"));
    }
    if jwk_field(&obj, "crv")? != "secp256k1" {
        return Err(invalid_key_err("Invalid curve: expected secp256k1"));
    }

    let signature_bytes = URL_SAFE_NO_PAD
        .decode(signature)
        .map_err(|err| jwt_err(err.to_string()))?;
    let signature =
        K256Signature::from_slice(&signature_bytes).map_err(|err| jwt_err(err.to_string()))?;

    if obj.get("d").is_some() {
        let d = decode_b64u_field(&obj, "d")?;
        if d.len() > 32 {
            return Err(invalid_key_err("invalid secp256k1 private key length"));
        }
        let padded = if d.len() < 32 {
            let mut out = vec![0_u8; 32 - d.len()];
            out.extend_from_slice(&d);
            out
        } else {
            d
        };
        let secret_key =
            K256SecretKey::from_slice(&padded).map_err(|err| invalid_key_err(err.to_string()))?;
        let signing_key = K256SigningKey::from(secret_key);
        return Ok(signing_key.verifying_key().verify(message, &signature).is_ok());
    }

    let x = decode_b64u_field(&obj, "x")?;
    let y = decode_b64u_field(&obj, "y")?;
    if x.len() > 32 || y.len() > 32 {
        return Err(invalid_key_err("invalid secp256k1 coordinate length"));
    }
    let mut encoded = Vec::with_capacity(65);
    encoded.push(0x04);
    encoded.extend(std::iter::repeat_n(0_u8, 32 - x.len()));
    encoded.extend_from_slice(&x);
    encoded.extend(std::iter::repeat_n(0_u8, 32 - y.len()));
    encoded.extend_from_slice(&y);
    let verifying_key = K256VerifyingKey::from_sec1_bytes(&encoded)
        .map_err(|err| invalid_key_err(err.to_string()))?;
    Ok(verifying_key.verify(message, &signature).is_ok())
}

#[pyfunction]
fn sign(message: &[u8], key: &Bound<'_, PyAny>, algorithm: &str) -> PyResult<String> {
    if algorithm == "none" {
        let key_bytes = extract_key_bytes(key)?;
        if key_bytes.is_empty() {
            return Ok(String::new());
        }
        return Err(invalid_key_err(
            "When alg = \"none\", key value must be None.",
        ));
    }

    let key_bytes = extract_key_bytes(key)?;

    if is_rsa_algorithm(algorithm) || is_ec_algorithm(algorithm) || algorithm == "EdDSA" {
        let usage = CacheUsage::Encode;
        let algorithm_name = normalize_algorithm_name(algorithm)?;
        let stored = build_stored_key_from_bytes(algorithm_name, &usage, &key_bytes)?;
        return sign_with_stored_key(message, &stored, algorithm);
    }

    let algorithm = parse_algorithm(algorithm)?;
    let encoding_key = build_encoding_key(algorithm, &key_bytes)?;
    crypto::sign(message, &encoding_key, algorithm).map_err(|err| jwt_err(err.to_string()))
}

#[pyfunction]
fn verify(
    signature: &str,
    message: &[u8],
    key: &Bound<'_, PyAny>,
    algorithm: &str,
) -> PyResult<bool> {
    if algorithm == "none" {
        return Ok(false);
    }

    let key_bytes = extract_key_bytes(key)?;

    if is_rsa_algorithm(algorithm) || is_ec_algorithm(algorithm) || algorithm == "EdDSA" {
        let usage = CacheUsage::Decode;
        let algorithm_name = normalize_algorithm_name(algorithm)?;
        let stored = build_stored_key_from_bytes(algorithm_name, &usage, &key_bytes)?;
        return verify_with_stored_key(signature, message, &stored, algorithm);
    }

    let algorithm = parse_algorithm(algorithm)?;
    let decoding_key = build_decoding_key(algorithm, &key_bytes)?;
    crypto::verify(signature, message, &decoding_key, algorithm)
        .map_err(|err| jwt_err(err.to_string()))
}

#[pyfunction]
fn decode_segments(token: &Bound<'_, PyAny>) -> PyResult<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)> {
    let token_bytes = extract_bytes_or_string(token, "token")?;
    decode_token_segments(&token_bytes)
}

#[pyfunction]
fn hash_digest(message: &[u8], algorithm: &str) -> PyResult<Vec<u8>> {
    compute_digest(message, algorithm)
}

#[pyfunction]
fn verify_with_jwk(signature: &str, message: &[u8], jwk_json: &str, algorithm: &str) -> PyResult<bool> {
    if algorithm == "none" {
        return Ok(false);
    }

    if algorithm == "ES512" || algorithm == "ES521" {
        return verify_es512_with_jwk(signature, message, jwk_json);
    }
    if algorithm == "ES256K" {
        return verify_es256k_with_jwk(signature, message, jwk_json);
    }

    let jwk: Jwk = serde_json::from_str(jwk_json).map_err(|err| invalid_key_err(err.to_string()))?;
    let normalized_algorithm = if algorithm == "ES521" {
        "ES512"
    } else {
        algorithm
    };
    let algorithm = parse_algorithm(normalized_algorithm)?;
    let decoding_key = DecodingKey::from_jwk(&jwk).map_err(|err| invalid_key_err(err.to_string()))?;
    crypto::verify(signature, message, &decoding_key, algorithm)
        .map_err(|err| jwt_err(err.to_string()))
}

#[pyfunction]
fn prepare_key_handle(
    key: &Bound<'_, PyAny>,
    algorithm: &str,
    usage: &str,
) -> PyResult<RustKeyHandle> {
    let key_bytes = extract_key_bytes(key)?;
    let algorithm_name: &'static str = match algorithm {
        "HS256" => "HS256",
        "HS384" => "HS384",
        "HS512" => "HS512",
        "RS256" => "RS256",
        "RS384" => "RS384",
        "RS512" => "RS512",
        "PS256" => "PS256",
        "PS384" => "PS384",
        "PS512" => "PS512",
        "ES256" => "ES256",
        "ES384" => "ES384",
        "ES512" => "ES512",
        "ES256K" => "ES256K",
        "EdDSA" => "EdDSA",
        "none" => "none",
        _ => return Err(invalid_algorithm_err(format!("unsupported algorithm: {algorithm}"))),
    };
    if algorithm_name == "none" {
        return put_handle(algorithm_name, CacheUsage::Encode, &key_bytes, || {
            Ok(StoredKey::Encoding(EncodingKey::from_secret(&[])))
        });
    }
    let usage_enum = match usage {
        "encode" => CacheUsage::Encode,
        "decode" => CacheUsage::Decode,
        _ => return Err(invalid_key_err("usage must be 'encode' or 'decode'")),
    };
    put_handle(algorithm_name, usage_enum.clone(), &key_bytes, || {
        build_stored_key_from_bytes(algorithm_name, &usage_enum, &key_bytes)
    })
}

#[pyfunction]
fn prepare_jwk_handle(jwk_json: &str, algorithm: &str, usage: &str) -> PyResult<RustKeyHandle> {
    let algorithm_name: &'static str = match algorithm {
        "HS256" => "HS256",
        "HS384" => "HS384",
        "HS512" => "HS512",
        "RS256" => "RS256",
        "RS384" => "RS384",
        "RS512" => "RS512",
        "PS256" => "PS256",
        "PS384" => "PS384",
        "PS512" => "PS512",
        "ES256" => "ES256",
        "ES384" => "ES384",
        "ES512" => "ES512",
        "ES256K" => "ES256K",
        "EdDSA" => "EdDSA",
        _ => return Err(invalid_algorithm_err(format!("unsupported algorithm: {algorithm}"))),
    };
    let usage_enum = match usage {
        "encode" => CacheUsage::Encode,
        "decode" => CacheUsage::Decode,
        _ => return Err(invalid_key_err("usage must be 'encode' or 'decode'")),
    };
    let cache_key_bytes = jwk_json.as_bytes().to_vec();
    put_handle(algorithm_name, usage_enum.clone(), &cache_key_bytes, || {
        let jwk: Jwk =
            serde_json::from_str(jwk_json).map_err(|err| invalid_key_err(err.to_string()))?;
        match usage_enum {
            CacheUsage::Encode => {
                if algorithm_name.starts_with("HS") {
                    let decoding_key = DecodingKey::from_jwk(&jwk)
                        .map_err(|err| invalid_key_err(err.to_string()))?;
                    let secret = decoding_key
                        .try_get_hmac_secret()
                        .map_err(|err| invalid_key_err(err.to_string()))?;
                    Ok(StoredKey::Encoding(EncodingKey::from_secret(secret)))
                } else {
                    Err(invalid_key_err("JWK encode handle is not supported for this algorithm"))
                }
            }
            CacheUsage::Decode => {
                if algorithm_name == "ES512" || algorithm_name == "ES256K" {
                    Err(invalid_key_err("Use verify_with_jwk for this algorithm"))
                } else {
                    let decoding_key = DecodingKey::from_jwk(&jwk)
                        .map_err(|err| invalid_key_err(err.to_string()))?;
                    Ok(StoredKey::Decoding(decoding_key))
                }
            }
        }
    })
}

#[pyfunction]
fn sign_prepared(message: &[u8], handle: &RustKeyHandle, algorithm: &str) -> PyResult<String> {
    let stored = stored_key_from_handle(handle)?;
    sign_with_stored_key(message, stored.as_ref(), algorithm)
}

#[pyfunction]
fn sign_prepared_raw(message: &[u8], handle: &RustKeyHandle, algorithm: &str) -> PyResult<Vec<u8>> {
    let stored = stored_key_from_handle(handle)?;
    sign_with_stored_key_raw(message, stored.as_ref(), algorithm)
}

#[pyfunction]
fn verify_prepared(
    signature: &str,
    message: &[u8],
    handle: &RustKeyHandle,
    algorithm: &str,
) -> PyResult<bool> {
    let stored = stored_key_from_handle(handle)?;
    verify_with_stored_key(signature, message, stored.as_ref(), algorithm)
}

#[pyfunction]
fn verify_prepared_raw(
    signature: &[u8],
    message: &[u8],
    handle: &RustKeyHandle,
    algorithm: &str,
) -> PyResult<bool> {
    let stored = stored_key_from_handle(handle)?;
    verify_with_stored_key_raw(signature, message, stored.as_ref(), algorithm)
}

#[pyfunction]
fn base64url_decode(input: &Bound<'_, PyAny>) -> PyResult<Vec<u8>> {
    let s = if let Ok(bytes) = input.extract::<Vec<u8>>() {
        String::from_utf8(bytes).map_err(|err| jwt_err(err.to_string()))?
    } else {
        input.extract::<String>().map_err(|_| {
            PyTypeError::new_err("argument 'input': must be str or bytes")
        })?
    };
    URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|err| jwt_err(err.to_string()))
}

#[pyfunction]
fn base64url_encode(input: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(input)
}

#[pyfunction]
fn supported_algorithms() -> Vec<&'static str> {
    vec![
        "HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256",
        "ES384", "ES512", "ES256K", "EdDSA", "none",
    ]
}

#[pymodule]
fn _rust_pyjwt(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("RustJWTError", py.get_type::<RustJWTError>())?;
    m.add("RustInvalidKeyError", py.get_type::<RustInvalidKeyError>())?;
    m.add(
        "RustInvalidAlgorithmError",
        py.get_type::<RustInvalidAlgorithmError>(),
    )?;
    m.add_class::<RustKeyHandle>()?;
    m.add_function(wrap_pyfunction!(sign, m)?)?;
    m.add_function(wrap_pyfunction!(verify, m)?)?;
    m.add_function(wrap_pyfunction!(prepare_key_handle, m)?)?;
    m.add_function(wrap_pyfunction!(prepare_jwk_handle, m)?)?;
    m.add_function(wrap_pyfunction!(sign_prepared, m)?)?;
    m.add_function(wrap_pyfunction!(sign_prepared_raw, m)?)?;
    m.add_function(wrap_pyfunction!(verify_prepared, m)?)?;
    m.add_function(wrap_pyfunction!(verify_prepared_raw, m)?)?;
    m.add_function(wrap_pyfunction!(decode_segments, m)?)?;
    m.add_function(wrap_pyfunction!(hash_digest, m)?)?;
    m.add_function(wrap_pyfunction!(verify_with_jwk, m)?)?;
    m.add_function(wrap_pyfunction!(base64url_decode, m)?)?;
    m.add_function(wrap_pyfunction!(base64url_encode, m)?)?;
    m.add_function(wrap_pyfunction!(supported_algorithms, m)?)?;
    Ok(())
}
