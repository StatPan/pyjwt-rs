use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ecdsa::signature::{Signer, Verifier};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, crypto};
use k256::ecdsa::{
    Signature as K256Signature, SigningKey as K256SigningKey, VerifyingKey as K256VerifyingKey,
};
use k256::elliptic_curve::pkcs8::{
    DecodePrivateKey as K256DecodePrivateKey, DecodePublicKey as K256DecodePublicKey,
};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{PublicKey as K256PublicKey, SecretKey as K256SecretKey};
use p521::ecdsa::{
    Signature as P521Signature, SigningKey as P521SigningKey, VerifyingKey as P521VerifyingKey,
};
use p521::{PublicKey as P521PublicKey, SecretKey as P521SecretKey};
use pyo3::exceptions::PyTypeError;
use pyo3::prelude::*;
use pyo3::types::PyAny;
use pyo3::{Bound, create_exception};

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

fn sign_es512(message: &[u8], key_bytes: &[u8]) -> PyResult<String> {
    let pem = std::str::from_utf8(key_bytes).map_err(|err| invalid_key_err(err.to_string()))?;

    let secret_key = P521SecretKey::from_pkcs8_pem(pem)
        .or_else(|_| P521SecretKey::from_sec1_pem(pem))
        .map_err(|err| invalid_key_err(err.to_string()))?;
    let secret_bytes = secret_key.to_bytes();
    let signing_key = P521SigningKey::from_slice(&secret_bytes)
        .map_err(|err| invalid_key_err(err.to_string()))?;
    let signature: P521Signature = signing_key.sign(message);
    Ok(URL_SAFE_NO_PAD.encode(signature.to_bytes()))
}

fn verify_es512(signature: &str, message: &[u8], key_bytes: &[u8]) -> PyResult<bool> {
    let pem = std::str::from_utf8(key_bytes).map_err(|err| invalid_key_err(err.to_string()))?;
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(signature)
        .map_err(|err| jwt_err(err.to_string()))?;
    let signature =
        P521Signature::from_slice(&signature_bytes).map_err(|err| jwt_err(err.to_string()))?;

    if let Ok(public_key) = P521PublicKey::from_public_key_pem(pem) {
        let encoded = public_key.to_encoded_point(false);
        let verifying_key = P521VerifyingKey::from_sec1_bytes(encoded.as_bytes())
            .map_err(|err| invalid_key_err(err.to_string()))?;
        return Ok(verifying_key.verify(message, &signature).is_ok());
    }

    let secret_key = P521SecretKey::from_pkcs8_pem(pem)
        .or_else(|_| P521SecretKey::from_sec1_pem(pem))
        .map_err(|err| invalid_key_err(err.to_string()))?;
    let secret_bytes = secret_key.to_bytes();
    let signing_key = P521SigningKey::from_slice(&secret_bytes)
        .map_err(|err| invalid_key_err(err.to_string()))?;
    let verifying_key = P521VerifyingKey::from(&signing_key);
    Ok(verifying_key.verify(message, &signature).is_ok())
}

fn sign_es256k(message: &[u8], key_bytes: &[u8]) -> PyResult<String> {
    let pem = std::str::from_utf8(key_bytes).map_err(|err| invalid_key_err(err.to_string()))?;

    let secret_key = K256SecretKey::from_pkcs8_pem(pem)
        .or_else(|_| K256SecretKey::from_sec1_pem(pem))
        .map_err(|err| invalid_key_err(err.to_string()))?;
    let signing_key = K256SigningKey::from(secret_key);
    let signature: K256Signature = signing_key.sign(message);
    Ok(URL_SAFE_NO_PAD.encode(signature.to_bytes()))
}

fn verify_es256k(signature: &str, message: &[u8], key_bytes: &[u8]) -> PyResult<bool> {
    let pem = std::str::from_utf8(key_bytes).map_err(|err| invalid_key_err(err.to_string()))?;
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(signature)
        .map_err(|err| jwt_err(err.to_string()))?;
    let signature =
        K256Signature::from_slice(&signature_bytes).map_err(|err| jwt_err(err.to_string()))?;

    if let Ok(public_key) = K256PublicKey::from_public_key_pem(pem) {
        let encoded = public_key.to_encoded_point(false);
        let verifying_key = K256VerifyingKey::from_sec1_bytes(encoded.as_bytes())
            .map_err(|err| invalid_key_err(err.to_string()))?;
        return Ok(verifying_key.verify(message, &signature).is_ok());
    }

    let secret_key = K256SecretKey::from_pkcs8_pem(pem)
        .or_else(|_| K256SecretKey::from_sec1_pem(pem))
        .map_err(|err| invalid_key_err(err.to_string()))?;
    let signing_key = K256SigningKey::from(secret_key);
    Ok(signing_key
        .verifying_key()
        .verify(message, &signature)
        .is_ok())
}

fn build_encoding_key(algorithm: Algorithm, key_bytes: &[u8]) -> PyResult<EncodingKey> {
    match algorithm {
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
            Ok(EncodingKey::from_secret(key_bytes))
        }
        Algorithm::RS256
        | Algorithm::RS384
        | Algorithm::RS512
        | Algorithm::PS256
        | Algorithm::PS384
        | Algorithm::PS512 => {
            EncodingKey::from_rsa_pem(key_bytes).map_err(|err| invalid_key_err(err.to_string()))
        }
        Algorithm::ES256 | Algorithm::ES384 => {
            EncodingKey::from_ec_pem(key_bytes).map_err(|err| invalid_key_err(err.to_string()))
        }
        Algorithm::EdDSA => {
            EncodingKey::from_ed_pem(key_bytes).map_err(|err| invalid_key_err(err.to_string()))
        }
    }
}

fn build_decoding_key(algorithm: Algorithm, key_bytes: &[u8]) -> PyResult<DecodingKey> {
    match algorithm {
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
            Ok(DecodingKey::from_secret(key_bytes))
        }
        Algorithm::RS256
        | Algorithm::RS384
        | Algorithm::RS512
        | Algorithm::PS256
        | Algorithm::PS384
        | Algorithm::PS512 => {
            DecodingKey::from_rsa_pem(key_bytes).map_err(|err| invalid_key_err(err.to_string()))
        }
        Algorithm::ES256 | Algorithm::ES384 => {
            DecodingKey::from_ec_pem(key_bytes).map_err(|err| invalid_key_err(err.to_string()))
        }
        Algorithm::EdDSA => {
            DecodingKey::from_ed_pem(key_bytes).map_err(|err| invalid_key_err(err.to_string()))
        }
    }
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

    if algorithm == "ES512" {
        return sign_es512(message, &key_bytes);
    }
    if algorithm == "ES256K" {
        return sign_es256k(message, &key_bytes);
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

    if algorithm == "ES512" {
        return verify_es512(signature, message, &key_bytes);
    }
    if algorithm == "ES256K" {
        return verify_es256k(signature, message, &key_bytes);
    }

    let algorithm = parse_algorithm(algorithm)?;
    let decoding_key = build_decoding_key(algorithm, &key_bytes)?;
    crypto::verify(signature, message, &decoding_key, algorithm)
        .map_err(|err| jwt_err(err.to_string()))
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
    m.add_function(wrap_pyfunction!(sign, m)?)?;
    m.add_function(wrap_pyfunction!(verify, m)?)?;
    m.add_function(wrap_pyfunction!(base64url_decode, m)?)?;
    m.add_function(wrap_pyfunction!(base64url_encode, m)?)?;
    m.add_function(wrap_pyfunction!(supported_algorithms, m)?)?;
    Ok(())
}
