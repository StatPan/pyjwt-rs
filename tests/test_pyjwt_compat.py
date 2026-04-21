import json
import warnings
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

import jwt_rs as jwt
from jwt_rs.warnings import InsecureKeyLengthWarning, RemovedInPyjwt3Warning

from .utils import HS256_SECRET


def test_roundtrip_hs256():
    token = jwt.encode(
        {"sub": "alice", "exp": int(datetime.now(tz=timezone.utc).timestamp()) + 300},
        HS256_SECRET,
        algorithm="HS256",
        headers={"kid": "dev-key"},
    )
    claims = jwt.decode(token, HS256_SECRET, algorithms=["HS256"])
    header = jwt.get_unverified_header(token)
    complete = jwt.decode_complete(token, HS256_SECRET, algorithms=["HS256"])

    assert claims["sub"] == "alice"
    assert header["kid"] == "dev-key"
    assert complete["payload"]["sub"] == "alice"
    assert isinstance(complete["signature"], bytes)


def test_encode_rejects_non_dict_payload():
    with pytest.raises(
        TypeError,
        match="Expecting a dict object, as JWT only supports JSON objects as payloads.",
    ):
        jwt.encode(["x"], "secret", algorithm="HS256")


def test_decode_requires_algorithms_when_verifying():
    token = jwt.encode({"a": 1}, HS256_SECRET, algorithm="HS256")
    with pytest.raises(
        jwt.DecodeError,
        match='It is required that you pass in a value for the "algorithms" argument',
    ):
        jwt.decode(token, HS256_SECRET)


def test_subject_and_required_claim_validation():
    token = jwt.encode({"sub": "alice"}, HS256_SECRET, algorithm="HS256")
    with pytest.raises(jwt.InvalidSubjectError, match="Invalid subject"):
        jwt.decode(token, HS256_SECRET, algorithms=["HS256"], subject="bob")
    with pytest.raises(jwt.MissingRequiredClaimError, match='Token is missing the "iss" claim'):
        jwt.decode(token, HS256_SECRET, algorithms=["HS256"], options={"require": ["iss"]})


def test_datetime_claims_and_expiration():
    token = jwt.encode(
        {"exp": datetime.now(tz=timezone.utc) - timedelta(seconds=1)},
        HS256_SECRET,
        algorithm="HS256",
    )
    with pytest.raises(jwt.ExpiredSignatureError, match="Signature has expired"):
        jwt.decode(token, HS256_SECRET, algorithms=["HS256"])


def test_decode_complete_detached_payload():
    payload = b'{"sub":"alice"}'
    token = jwt.api_jws.PyJWS().encode(
        payload,
        HS256_SECRET,
        algorithm="HS256",
        headers={"b64": False, "crit": ["b64"]},
        is_payload_detached=True,
    )
    decoded = jwt.decode_complete(
        token,
        HS256_SECRET,
        algorithms=["HS256"],
        detached_payload=payload,
        options={"verify_signature": True},
    )
    assert decoded["payload"]["sub"] == "alice"


def test_deprecated_kwargs_warning():
    token = jwt.encode({"a": 1}, HS256_SECRET, algorithm="HS256")
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        jwt.decode(token, HS256_SECRET, algorithms=["HS256"], foo="bar")
    assert any(isinstance(w.message, RemovedInPyjwt3Warning) for w in caught)


def test_insecure_hmac_key_warning():
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        jwt.encode({"a": 1}, "secret", algorithm="HS256")
    assert any(isinstance(w.message, InsecureKeyLengthWarning) for w in caught)


def test_none_algorithm_encoding():
    token = jwt.encode({"a": 1}, key="", algorithm=None)
    assert token.endswith(".")
    decoded = jwt.decode(token, key="", algorithms=["none"], options={"verify_signature": False})
    assert decoded == {"a": 1}


def test_get_algorithm_by_name_returns_algorithm_object():
    alg = jwt.get_algorithm_by_name("HS256")
    assert alg.__class__.__name__ == "HMACAlgorithm"
    assert jwt.algorithms.get_default_algorithms()["ES521"].__class__.__name__ == "ECAlgorithm"


def test_algorithm_to_jwk_and_from_jwk_roundtrip_hmac():
    alg = jwt.get_algorithm_by_name("HS256")
    jwk_dict = alg.to_jwk("secret", as_dict=True)
    assert jwk_dict["kty"] == "oct"
    assert alg.from_jwk(jwk_dict) == b"secret"


def test_register_custom_algorithm_roundtrip():
    class DemoAlgorithm(jwt.algorithms.Algorithm):
        def prepare_key(self, key):
            return key

        def sign(self, msg, key):
            return b"sig:" + msg

        def verify(self, msg, key, sig):
            return sig == b"sig:" + msg

        @staticmethod
        def to_jwk(key_obj, as_dict=False):
            obj = {"kty": "oct", "k": "ZGVtbw"}
            return obj if as_dict else json.dumps(obj)

        @staticmethod
        def from_jwk(jwk):
            return b"demo"

    jws = jwt.PyJWS()
    jws.register_algorithm("DEMO", DemoAlgorithm())
    token = jws.encode(b'{"a":1}', "ignored", algorithm="DEMO")
    decoded = jws.decode(token, "ignored", algorithms=["DEMO"])
    assert decoded == b'{"a":1}'
    jws.unregister_algorithm("DEMO")


def test_bad_segments_error():
    with pytest.raises(jwt.DecodeError, match="Not enough segments"):
        jwt.decode("abc", "secret", algorithms=["HS256"])


def test_header_sorting_toggle():
    token1 = jwt.encode({"a": 1}, HS256_SECRET, algorithm="HS256", headers={"z": 1, "a": 2})
    token2 = jwt.encode(
        {"a": 1},
        HS256_SECRET,
        algorithm="HS256",
        headers={"z": 1, "a": 2},
        sort_headers=False,
    )
    header1 = json.loads(jwt.api_jws.base64url_decode(token1.split(".")[0]).decode())
    header2 = json.loads(jwt.api_jws.base64url_decode(token2.split(".")[0]).decode())
    assert list(header1.keys()) != list(header2.keys())


def _b64u_uint(value: int) -> str:
    length = max(1, (value.bit_length() + 7) // 8)
    return jwt.api_jws.base64url_encode(value.to_bytes(length, "big"))


def test_pyjwk_rsa_public_key_decode():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_numbers = private_key.public_key().public_numbers()
    jwk_dict = {
        "kty": "RSA",
        "kid": "rsa-1",
        "alg": "RS256",
        "use": "sig",
        "n": _b64u_uint(public_numbers.n),
        "e": _b64u_uint(public_numbers.e),
    }
    pyjwk = jwt.PyJWK.from_dict(jwk_dict)

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    token = jwt.encode({"sub": "alice"}, private_pem, algorithm="RS256", headers={"kid": "rsa-1"})
    claims = jwt.decode(token, pyjwk, algorithms=None)
    assert claims["sub"] == "alice"


def test_pyjwk_okp_public_key_decode():
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    public_raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    jwk_dict = {
        "kty": "OKP",
        "kid": "eddsa-1",
        "alg": "EdDSA",
        "crv": "Ed25519",
        "x": jwt.api_jws.base64url_encode(public_raw),
    }
    pyjwk = jwt.PyJWK.from_dict(jwk_dict)

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    token = jwt.encode({"sub": "alice"}, private_pem, algorithm="EdDSA", headers={"kid": "eddsa-1"})
    claims = jwt.decode(token, pyjwk)
    assert claims["sub"] == "alice"


def test_es512_roundtrip_and_pyjwk_decode():
    private_key = ec.generate_private_key(ec.SECP521R1())
    public_numbers = private_key.public_key().public_numbers()
    jwk_dict = {
        "kty": "EC",
        "kid": "p521-1",
        "alg": "ES512",
        "use": "sig",
        "crv": "P-521",
        "x": _b64u_uint(public_numbers.x),
        "y": _b64u_uint(public_numbers.y),
    }
    pyjwk = jwt.PyJWK.from_dict(jwk_dict)

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    token = jwt.encode({"sub": "alice"}, private_pem, algorithm="ES512", headers={"kid": "p521-1"})
    claims = jwt.decode(token, pyjwk)
    assert claims["sub"] == "alice"


def test_es256k_roundtrip_and_pyjwk_decode():
    private_key = ec.generate_private_key(ec.SECP256K1())
    public_numbers = private_key.public_key().public_numbers()
    jwk_dict = {
        "kty": "EC",
        "kid": "k256-1",
        "alg": "ES256K",
        "use": "sig",
        "crv": "secp256k1",
        "x": _b64u_uint(public_numbers.x),
        "y": _b64u_uint(public_numbers.y),
    }
    pyjwk = jwt.PyJWK.from_dict(jwk_dict)

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    token = jwt.encode({"sub": "alice"}, private_pem, algorithm="ES256K", headers={"kid": "k256-1"})
    claims = jwt.decode(token, pyjwk)
    assert claims["sub"] == "alice"


def test_pyjwkclient_fetches_matching_key():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_numbers = private_key.public_key().public_numbers()
    jwks = {
        "keys": [
            {
                "kty": "RSA",
                "kid": "rsa-client",
                "alg": "RS256",
                "use": "sig",
                "n": _b64u_uint(public_numbers.n),
                "e": _b64u_uint(public_numbers.e),
            }
        ]
    }

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = json.dumps(jwks).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        client = jwt.PyJWKClient(f"http://127.0.0.1:{server.server_port}/jwks")
        signing_key = client.get_signing_key("rsa-client")
        assert signing_key.key_id == "rsa-client"

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        token = jwt.encode({"sub": "alice"}, private_pem, algorithm="RS256", headers={"kid": "rsa-client"})
        fetched = client.get_signing_key_from_jwt(token)
        assert fetched.key_id == "rsa-client"
    finally:
        server.shutdown()
        server.server_close()
