from __future__ import annotations

import hashlib
import hmac
import json
import sys
from abc import ABC, abstractmethod
from collections.abc import Hashable
from typing import Any, ClassVar, Literal, overload

if sys.version_info >= (3, 11):
    from typing import Never
else:
    from typing import NoReturn as Never

from ._rust_pyjwt import (
    RustInvalidAlgorithmError,
    RustInvalidKeyError,
    RustJWTError,
    RustKeyHandle,
    base64url_decode,
    base64url_encode,
    hash_digest as rust_hash_digest,
    prepare_jwk_handle as rust_prepare_jwk_handle,
    prepare_key_handle as rust_prepare_key_handle,
    sign as rust_sign,
    sign_prepared as rust_sign_prepared,
    sign_prepared_raw as rust_sign_prepared_raw,
    verify as rust_verify,
    verify_prepared as rust_verify_prepared,
    verify_prepared_raw as rust_verify_prepared_raw,
)
from .exceptions import InvalidKeyError
from .types import HashlibHash, JWKDict

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, rsa

    has_crypto = True
    AllowedRSAKeys = rsa.RSAPrivateKey | rsa.RSAPublicKey
    AllowedECKeys = ec.EllipticCurvePrivateKey | ec.EllipticCurvePublicKey
    AllowedOKPKeys = ed25519.Ed25519PrivateKey | ed25519.Ed25519PublicKey | ed448.Ed448PrivateKey | ed448.Ed448PublicKey
except ModuleNotFoundError:
    has_crypto = False
    AllowedRSAKeys = Never  # type: ignore[assignment,misc]
    AllowedECKeys = Never  # type: ignore[assignment,misc]
    AllowedOKPKeys = Never  # type: ignore[assignment,misc]


requires_cryptography = {
    "RS256",
    "RS384",
    "RS512",
    "ES256",
    "ES256K",
    "ES384",
    "ES521",
    "ES512",
    "PS256",
    "PS384",
    "PS512",
    "EdDSA",
}

_HANDLE_CACHE: dict[tuple[str, str, Hashable], RustKeyHandle] = {}


def _cache_key_value(key: Any) -> Hashable | None:
    if isinstance(key, bytes):
        return key
    if isinstance(key, str):
        return key.encode("utf-8")
    if isinstance(key, RustKeyHandle):
        return ("handle", key.id)
    if isinstance(key, dict):
        return json.dumps(key, sort_keys=True, separators=(",", ":"))
    return None


def prepare_rust_handle(key: Any, algorithm: str, usage: str) -> RustKeyHandle | None:
    cache_value = _cache_key_value(key)
    if cache_value is None:
        return None
    cache_key = (algorithm, usage, cache_value)
    cached = _HANDLE_CACHE.get(cache_key)
    if cached is not None:
        return cached
    try:
        handle = rust_prepare_key_handle(key, algorithm, usage)
    except (RustInvalidKeyError, RustInvalidAlgorithmError, TypeError):
        return None
    _HANDLE_CACHE[cache_key] = handle
    return handle


def prepare_rust_jwk_handle(jwk: str | JWKDict, algorithm: str, usage: str) -> RustKeyHandle | None:
    jwk_json = json.dumps(jwk, sort_keys=True, separators=(",", ":")) if isinstance(jwk, dict) else jwk
    cache_key = (algorithm, usage, jwk_json)
    cached = _HANDLE_CACHE.get(cache_key)
    if cached is not None:
        return cached
    try:
        handle = rust_prepare_jwk_handle(jwk_json, algorithm, usage)
    except (RustInvalidKeyError, RustInvalidAlgorithmError, TypeError):
        return None
    _HANDLE_CACHE[cache_key] = handle
    return handle


def force_bytes(value: str | bytes) -> bytes:
    return value.encode("utf-8") if isinstance(value, str) else value


def is_pem_format(value: bytes) -> bool:
    return value.strip().startswith(b"-----BEGIN ")


def is_ssh_key(value: bytes) -> bool:
    stripped = value.strip()
    return (
        stripped.startswith(b"ssh-rsa")
        or stripped.startswith(b"ssh-ed25519")
        or stripped.startswith(b"ecdsa-sha2-")
    )


def _int_to_b64u(value: int) -> str:
    length = max(1, (value.bit_length() + 7) // 8)
    return base64url_encode(value.to_bytes(length, "big"))


def _b64u_to_int(value: str) -> int:
    return int.from_bytes(base64url_decode(value), "big")


def _serialize_private_key(key: Any) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _serialize_public_key(key: Any) -> bytes:
    return key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


class Algorithm(ABC):
    @abstractmethod
    def prepare_key(self, key: Any) -> Any:
        pass

    @abstractmethod
    def sign(self, msg: bytes, key: Any) -> bytes:
        pass

    @abstractmethod
    def verify(self, msg: bytes, key: Any, sig: bytes) -> bool:
        pass

    @overload
    @staticmethod
    @abstractmethod
    def to_jwk(key_obj: Any, as_dict: Literal[True]) -> JWKDict: ...

    @overload
    @staticmethod
    @abstractmethod
    def to_jwk(key_obj: Any, as_dict: Literal[False] = False) -> str: ...

    @staticmethod
    @abstractmethod
    def to_jwk(key_obj: Any, as_dict: bool = False) -> JWKDict | str:
        pass

    @staticmethod
    @abstractmethod
    def from_jwk(jwk: str | JWKDict) -> Any:
        pass

    def check_key_length(self, key: Any) -> str | None:
        return None

    _crypto_key_types: ClassVar[tuple[type, ...] | None] = None

    def check_crypto_key_type(self, key: Any) -> None:
        if not has_crypto or self._crypto_key_types is None:
            raise ValueError(
                "This method requires the cryptography library, and should only be used by cryptography-based algorithms."
            )
        if not isinstance(key, self._crypto_key_types):
            valid_classes = tuple(cls.__name__ for cls in self._crypto_key_types)
            raise InvalidKeyError(
                f"Expected one of {valid_classes}, got: {key.__class__.__name__}. Invalid Key type for {self.__class__.__name__}"
            )


class NoneAlgorithm(Algorithm):
    def prepare_key(self, key: str | None) -> None:
        if key == "":
            key = None
        if key is not None:
            raise InvalidKeyError('When alg = "none", key value must be None.')
        return key

    def sign(self, msg: bytes, key: None) -> bytes:
        return b""

    def verify(self, msg: bytes, key: None, sig: bytes) -> bool:
        return False

    @staticmethod
    def to_jwk(key_obj: Any, as_dict: bool = False) -> JWKDict | str:
        raise NotImplementedError()

    @staticmethod
    def from_jwk(jwk: str | JWKDict) -> Any:
        raise NotImplementedError()


class HMACAlgorithm(Algorithm):
    SHA256: ClassVar[HashlibHash] = hashlib.sha256
    SHA384: ClassVar[HashlibHash] = hashlib.sha384
    SHA512: ClassVar[HashlibHash] = hashlib.sha512

    _hash_to_name: ClassVar[dict] = {
        hashlib.sha256: "HS256",
        hashlib.sha384: "HS384",
        hashlib.sha512: "HS512",
    }

    def __init__(self, hash_alg: HashlibHash) -> None:
        name = self._hash_to_name.get(hash_alg)
        if name is None:
            raise InvalidKeyError(f"Unsupported HMAC hash algorithm: {hash_alg}")
        self.name = name
        self.hash_alg = hash_alg

    def prepare_key(self, key: str | bytes) -> bytes:
        if not isinstance(key, (str, bytes)):
            raise TypeError("Expected a string value")
        key_bytes = force_bytes(key)
        if is_pem_format(key_bytes) or is_ssh_key(key_bytes):
            raise InvalidKeyError(
                "The specified key is an asymmetric key or x509 certificate and should not be used as an HMAC secret."
            )
        return key_bytes

    def check_key_length(self, key: bytes) -> str | None:
        min_length = self.hash_alg().digest_size
        if len(key) < min_length:
            return (
                f"The HMAC key is {len(key)} bytes long, which is below "
                f"the minimum recommended length of {min_length} bytes for "
                f"{self.hash_alg().name.upper()}. See RFC 7518 Section 3.2."
            )
        return None

    def sign(self, msg: bytes, key: bytes) -> bytes:
        try:
            if isinstance(key, RustKeyHandle):
                return rust_sign_prepared_raw(msg, key, self.name)
            return base64url_decode(rust_sign(msg, key, self.name))
        except RustInvalidAlgorithmError as exc:
            raise NotImplementedError("Algorithm not supported") from exc
        except RustInvalidKeyError as exc:
            raise InvalidKeyError(str(exc)) from exc
        except RustJWTError as exc:
            raise InvalidKeyError(str(exc)) from exc

    def verify(self, msg: bytes, key: bytes, sig: bytes) -> bool:
        try:
            if isinstance(key, RustKeyHandle):
                return rust_verify_prepared_raw(sig, msg, key, self.name)
            return rust_verify(base64url_encode(sig), msg, key, self.name)
        except RustInvalidAlgorithmError as exc:
            raise NotImplementedError("Algorithm not supported") from exc
        except RustInvalidKeyError as exc:
            raise InvalidKeyError(str(exc)) from exc
        except RustJWTError:
            return False

    @overload
    @staticmethod
    def to_jwk(key_obj: str | bytes, as_dict: Literal[True]) -> JWKDict: ...

    @overload
    @staticmethod
    def to_jwk(key_obj: str | bytes, as_dict: Literal[False] = False) -> str: ...

    @staticmethod
    def to_jwk(key_obj: str | bytes, as_dict: bool = False) -> JWKDict | str:
        jwk = {"k": base64url_encode(force_bytes(key_obj)), "kty": "oct"}
        return jwk if as_dict else json.dumps(jwk)

    def compute_hash_digest(self, msg: bytes) -> bytes:
        try:
            return rust_hash_digest(msg, self.name)
        except RustInvalidAlgorithmError as exc:
            raise NotImplementedError("Algorithm not supported") from exc
        except RustJWTError as exc:
            raise InvalidKeyError(str(exc)) from exc

    @staticmethod
    def from_jwk(jwk: str | JWKDict) -> bytes:
        try:
            obj = json.loads(jwk) if isinstance(jwk, str) else jwk
        except ValueError:
            raise InvalidKeyError("Key is not valid JSON") from None
        if not isinstance(obj, dict) or obj.get("kty") != "oct":
            raise InvalidKeyError("Not an HMAC key")
        return base64url_decode(obj["k"])


def _key_to_pem(key: Any) -> bytes:
    if isinstance(key, (str, bytes)):
        return force_bytes(key)
    if not has_crypto:
        raise InvalidKeyError("cryptography is required")
    if isinstance(key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey)):
        return _serialize_private_key(key)
    if isinstance(key, (rsa.RSAPublicKey, ec.EllipticCurvePublicKey, ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
        return _serialize_public_key(key)
    raise InvalidKeyError(f"Unsupported key type: {type(key)}")


class _RustBackedAlgorithm(Algorithm):
    def __init__(self, name: str) -> None:
        self.name = name

    def sign(self, msg: bytes, key: Any) -> bytes:
        try:
            if isinstance(key, RustKeyHandle):
                return rust_sign_prepared_raw(msg, key, self.name)
            return base64url_decode(rust_sign(msg, _key_to_pem(key), self.name))
        except RustInvalidAlgorithmError as exc:
            raise NotImplementedError("Algorithm not supported") from exc
        except RustInvalidKeyError as exc:
            raise InvalidKeyError(str(exc)) from exc
        except RustJWTError as exc:
            raise InvalidKeyError(str(exc)) from exc

    def verify(self, msg: bytes, key: Any, sig: bytes) -> bool:
        try:
            if isinstance(key, RustKeyHandle):
                return rust_verify_prepared_raw(sig, msg, key, self.name)
            return rust_verify(base64url_encode(sig), msg, _key_to_pem(key), self.name)
        except RustInvalidAlgorithmError as exc:
            raise NotImplementedError("Algorithm not supported") from exc
        except RustInvalidKeyError as exc:
            raise InvalidKeyError(str(exc)) from exc
        except RustJWTError:
            return False


class RSAAlgorithm(_RustBackedAlgorithm):
    _MIN_KEY_SIZE: ClassVar[int] = 2048
    _alg_prefix: ClassVar[str] = "RS"

    def __init__(self, hash_alg: Any) -> None:
        if isinstance(hash_alg, str):
            super().__init__(hash_alg)
            return
        hash_name = hash_alg.name.lower()
        suffix_map = {"sha256": "256", "sha384": "384", "sha512": "512"}
        suffix = suffix_map.get(hash_name)
        if suffix is None:
            raise InvalidKeyError(f"Unsupported RSA hash algorithm: {hash_alg}")
        super().__init__(f"{self._alg_prefix}{suffix}")
        self.hash_alg = hash_alg

    def prepare_key(self, key: Any) -> AllowedRSAKeys:
        if not has_crypto:
            raise InvalidKeyError("cryptography is required")
        if isinstance(key, (rsa.RSAPrivateKey, rsa.RSAPublicKey)):
            return key
        if isinstance(key, (str, bytes)):
            key_bytes = force_bytes(key)
            try:
                if key_bytes.startswith(b"ssh-rsa"):
                    loaded = serialization.load_ssh_public_key(key_bytes)
                    if not isinstance(loaded, rsa.RSAPublicKey):
                        raise InvalidKeyError("Expected an RSA key")
                    return loaded
                try:
                    loaded = serialization.load_pem_private_key(key_bytes, password=None)
                except ValueError:
                    loaded = serialization.load_pem_public_key(key_bytes)
                if isinstance(loaded, (rsa.RSAPrivateKey, rsa.RSAPublicKey)):
                    return loaded
            except (ValueError, TypeError):
                raise InvalidKeyError("Could not parse the provided public key.") from None
            raise InvalidKeyError("Expected an RSA key")
        raise TypeError("Expecting a PEM-formatted key.")

    def check_key_length(self, key: Any) -> str | None:
        if isinstance(key, (rsa.RSAPrivateKey, rsa.RSAPublicKey)):
            key_size = key.key_size
        else:
            try:
                loaded = serialization.load_pem_private_key(key, password=None)
                key_size = loaded.key_size if isinstance(loaded, rsa.RSAPrivateKey) else None
            except (ValueError, TypeError):
                try:
                    loaded = serialization.load_pem_public_key(key)
                    key_size = loaded.key_size if isinstance(loaded, rsa.RSAPublicKey) else None
                except Exception:
                    return None
        if key_size is not None and key_size < self._MIN_KEY_SIZE:
            return (
                f"The RSA key is {key_size} bits long, which is below "
                f"the minimum recommended size of {self._MIN_KEY_SIZE} bits. "
                f"See NIST SP 800-131A."
            )
        return None

    def compute_hash_digest(self, msg: bytes) -> bytes:
        try:
            return rust_hash_digest(msg, self.name)
        except RustInvalidAlgorithmError as exc:
            raise NotImplementedError("Algorithm not supported") from exc
        except RustJWTError as exc:
            raise InvalidKeyError(str(exc)) from exc

    @overload
    @staticmethod
    def to_jwk(key_obj: Any, as_dict: Literal[True]) -> JWKDict: ...

    @overload
    @staticmethod
    def to_jwk(key_obj: Any, as_dict: Literal[False] = False) -> str: ...

    @staticmethod
    def to_jwk(key_obj: Any, as_dict: bool = False) -> JWKDict | str:
        if isinstance(key_obj, (str, bytes)):
            prepared = RSAAlgorithm("RS256").prepare_key(key_obj)
            try:
                key_obj = serialization.load_pem_private_key(prepared, password=None)
            except ValueError:
                key_obj = serialization.load_pem_public_key(prepared)
        if isinstance(key_obj, rsa.RSAPrivateKey):
            numbers = key_obj.private_numbers()
            obj = {
                "kty": "RSA",
                "key_ops": ["sign"],
                "n": _int_to_b64u(numbers.public_numbers.n),
                "e": _int_to_b64u(numbers.public_numbers.e),
                "d": _int_to_b64u(numbers.d),
                "p": _int_to_b64u(numbers.p),
                "q": _int_to_b64u(numbers.q),
                "dp": _int_to_b64u(numbers.dmp1),
                "dq": _int_to_b64u(numbers.dmq1),
                "qi": _int_to_b64u(numbers.iqmp),
            }
        elif isinstance(key_obj, rsa.RSAPublicKey):
            numbers = key_obj.public_numbers()
            obj = {
                "kty": "RSA",
                "key_ops": ["verify"],
                "n": _int_to_b64u(numbers.n),
                "e": _int_to_b64u(numbers.e),
            }
        else:
            raise InvalidKeyError("Not a public or private key")
        return obj if as_dict else json.dumps(obj)

    @staticmethod
    def from_jwk(jwk: str | JWKDict) -> AllowedRSAKeys:
        try:
            obj = json.loads(jwk) if isinstance(jwk, str) else jwk
        except ValueError:
            raise InvalidKeyError("Key is not valid JSON") from None
        if not isinstance(obj, dict) or obj.get("kty") != "RSA":
            raise InvalidKeyError("Not an RSA key")
        try:
            n = _b64u_to_int(obj["n"])
            e = _b64u_to_int(obj["e"])
        except KeyError as exc:
            raise InvalidKeyError(f"Missing required RSA key field: {exc}") from exc
        except Exception as exc:
            raise InvalidKeyError(str(exc)) from exc
        if "d" in obj:
            if "oth" in obj:
                raise InvalidKeyError("Unsupported RSA private key: > 2 primes not supported")
            d = _b64u_to_int(obj["d"])
            prime_fields = {"p", "q", "dp", "dq", "qi"}
            present = prime_fields & obj.keys()
            if present and present != prime_fields:
                raise InvalidKeyError("RSA private key is missing required fields")
            public_numbers = rsa.RSAPublicNumbers(e=e, n=n)
            if not present:
                from cryptography.hazmat.primitives.asymmetric.rsa import rsa_recover_prime_factors
                p, q = rsa_recover_prime_factors(n, e, d)
                dp = rsa.rsa_crt_dmp1(d, p)
                dq = rsa.rsa_crt_dmq1(d, q)
                qi = rsa.rsa_crt_iqmp(p, q)
            else:
                p = _b64u_to_int(obj["p"])
                q = _b64u_to_int(obj["q"])
                dp = _b64u_to_int(obj["dp"])
                dq = _b64u_to_int(obj["dq"])
                qi = _b64u_to_int(obj["qi"])
            private_numbers = rsa.RSAPrivateNumbers(
                p=p, q=q, d=d, dmp1=dp, dmq1=dq, iqmp=qi,
                public_numbers=public_numbers,
            )
            return private_numbers.private_key()
        return rsa.RSAPublicNumbers(e=e, n=n).public_key()


class RSAPSSAlgorithm(RSAAlgorithm):
    _alg_prefix: ClassVar[str] = "PS"


_EC_CURVE_TO_ALG: dict[Any, str] = {}
_EC_ALG_TO_CURVE: dict[str, Any] = {}
_EC_HASH_DEFAULT: dict[str, tuple[str, Any]] = {}

if has_crypto:
    from cryptography.hazmat.primitives import hashes as _hashes

    RSAAlgorithm.SHA256 = _hashes.SHA256()  # type: ignore[attr-defined]
    RSAAlgorithm.SHA384 = _hashes.SHA384()  # type: ignore[attr-defined]
    RSAAlgorithm.SHA512 = _hashes.SHA512()  # type: ignore[attr-defined]

    _EC_CURVE_TO_ALG = {
        ec.SECP256R1: "ES256",
        ec.SECP384R1: "ES384",
        ec.SECP521R1: "ES512",
        ec.SECP256K1: "ES256K",
    }
    _EC_ALG_TO_CURVE = {v: k for k, v in _EC_CURVE_TO_ALG.items()}
    _EC_HASH_DEFAULT = {
        "sha256": ("ES256", ec.SECP256R1),
        "sha384": ("ES384", ec.SECP384R1),
        "sha512": ("ES512", ec.SECP521R1),
    }



class ECAlgorithm(_RustBackedAlgorithm):
    def __init__(self, hash_alg: Any, expected_curve: Any = None) -> None:
        if isinstance(hash_alg, str):
            # backward compat: ECAlgorithm("ES256", "P-256", ec.SECP256R1)
            # In this case hash_alg is actually the name string
            name = hash_alg
            if expected_curve is not None and not isinstance(expected_curve, str):
                self.expected_curve = expected_curve if isinstance(expected_curve, type) else type(expected_curve)
            else:
                self.expected_curve = None
            super().__init__(name)
            return

        hash_name = hash_alg.name.lower()
        if expected_curve is not None:
            curve_cls = expected_curve if isinstance(expected_curve, type) else type(expected_curve)
            name = _EC_CURVE_TO_ALG.get(curve_cls)
            if name is None:
                raise InvalidKeyError(f"Unsupported EC curve: {expected_curve}")
            self.expected_curve: type | None = curve_cls
        else:
            default = _EC_HASH_DEFAULT.get(hash_name)
            if default is None:
                raise InvalidKeyError(f"Unsupported EC hash algorithm: {hash_alg}")
            name, _ = default
            self.expected_curve = None
        super().__init__(name)
        self.hash_alg = hash_alg

    def _validate_curve(self, key: Any) -> None:
        if self.expected_curve is None:
            return
        if not isinstance(key.curve, self.expected_curve):
            raise InvalidKeyError(
                f"The key's curve '{key.curve.name}' does not match the expected curve "
                f"'{self.expected_curve().name}' for this algorithm"
            )

    def prepare_key(self, key: Any) -> AllowedECKeys:
        if not has_crypto:
            raise InvalidKeyError("cryptography is required")
        if key is None or (not isinstance(key, (str, bytes, ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey))):
            raise TypeError("Expecting a PEM-formatted or EC key.")
        if isinstance(key, (ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey)):
            self._validate_curve(key)
            return key
        if isinstance(key, (str, bytes)):
            key_bytes = force_bytes(key)
            try:
                try:
                    loaded = (
                        serialization.load_ssh_public_key(key_bytes)
                        if key_bytes.startswith(b"ecdsa-sha2-")
                        else serialization.load_pem_public_key(key_bytes)
                    )
                except ValueError:
                    loaded = serialization.load_pem_private_key(key_bytes, password=None)
            except (ValueError, TypeError):
                raise InvalidKeyError("Expecting a PEM-formatted key.") from None
        else:
            loaded = key
        if isinstance(loaded, ec.EllipticCurvePrivateKey):
            self._validate_curve(loaded)
            return loaded
        if isinstance(loaded, ec.EllipticCurvePublicKey):
            self._validate_curve(loaded)
            return loaded
        raise InvalidKeyError("Expecting a PEM-formatted key.")

    def _alg_for_key(self, key: Any) -> str:
        if isinstance(key, (ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey)):
            alg = _EC_CURVE_TO_ALG.get(type(key.curve))
            if alg is not None:
                return alg
        return self.name

    def sign(self, msg: bytes, key: Any) -> bytes:
        try:
            if isinstance(key, RustKeyHandle):
                return rust_sign_prepared_raw(msg, key, self.name)
            return base64url_decode(rust_sign(msg, _key_to_pem(key), self._alg_for_key(key)))
        except RustInvalidAlgorithmError as exc:
            raise NotImplementedError("Algorithm not supported") from exc
        except RustInvalidKeyError as exc:
            raise InvalidKeyError(str(exc)) from exc
        except RustJWTError as exc:
            raise InvalidKeyError(str(exc)) from exc

    def verify(self, msg: bytes, key: Any, sig: bytes) -> bool:
        try:
            if isinstance(key, RustKeyHandle):
                return rust_verify_prepared_raw(sig, msg, key, self.name)
            return rust_verify(base64url_encode(sig), msg, _key_to_pem(key), self._alg_for_key(key))
        except RustInvalidAlgorithmError as exc:
            raise NotImplementedError("Algorithm not supported") from exc
        except RustInvalidKeyError as exc:
            raise InvalidKeyError(str(exc)) from exc
        except RustJWTError:
            return False

    @overload
    @staticmethod
    def to_jwk(key_obj: Any, as_dict: Literal[True]) -> JWKDict: ...

    @overload
    @staticmethod
    def to_jwk(key_obj: Any, as_dict: Literal[False] = False) -> str: ...

    @staticmethod
    def to_jwk(key_obj: Any, as_dict: bool = False) -> JWKDict | str:
        if isinstance(key_obj, (str, bytes)):
            key_bytes = force_bytes(key_obj)
            try:
                key_obj = serialization.load_pem_private_key(key_bytes, password=None)
            except ValueError:
                key_obj = serialization.load_pem_public_key(key_bytes)
        if isinstance(key_obj, ec.EllipticCurvePrivateKey):
            public_numbers = key_obj.public_key().public_numbers()
            private_value = key_obj.private_numbers().private_value
        elif isinstance(key_obj, ec.EllipticCurvePublicKey):
            public_numbers = key_obj.public_numbers()
            private_value = None
        else:
            raise InvalidKeyError("Not a public or private key")

        curve_map = {
            "secp256r1": "P-256",
            "secp384r1": "P-384",
            "secp521r1": "P-521",
            "secp256k1": "secp256k1",
        }
        crv = curve_map.get(public_numbers.curve.name)
        if crv is None:
            raise InvalidKeyError("Invalid curve")

        obj: JWKDict = {
            "kty": "EC",
            "crv": crv,
            "x": _int_to_b64u(public_numbers.x),
            "y": _int_to_b64u(public_numbers.y),
        }
        if private_value is not None:
            obj["d"] = _int_to_b64u(private_value)
        return obj if as_dict else json.dumps(obj)

    @staticmethod
    def from_jwk(jwk: str | JWKDict) -> AllowedECKeys:
        try:
            obj = json.loads(jwk) if isinstance(jwk, str) else jwk
        except ValueError:
            raise InvalidKeyError("Key is not valid JSON") from None
        if not isinstance(obj, dict) or obj.get("kty") != "EC":
            raise InvalidKeyError("Not an EC key")
        crv = obj.get("crv")
        curve_info: dict[str | None, tuple[Any, int]] = {
            "P-256": (ec.SECP256R1(), 32),
            "P-384": (ec.SECP384R1(), 48),
            "P-521": (ec.SECP521R1(), 66),
            "secp256k1": (ec.SECP256K1(), 32),
        }
        info = curve_info.get(crv)
        if info is None:
            raise InvalidKeyError(f"Invalid curve: {crv}")
        curve, coord_len = info
        try:
            x_bytes = base64url_decode(obj["x"])
            y_bytes = base64url_decode(obj["y"])
        except KeyError as exc:
            raise InvalidKeyError(f"Missing required field: {exc}") from exc
        except Exception as exc:
            raise InvalidKeyError(str(exc)) from exc
        if len(x_bytes) > coord_len or len(y_bytes) > coord_len:
            raise InvalidKeyError(
                f"EC coordinate length {len(x_bytes)} exceeds expected {coord_len} for {crv}"
            )
        x_bytes = x_bytes.rjust(coord_len, b"\x00")
        y_bytes = y_bytes.rjust(coord_len, b"\x00")
        x = int.from_bytes(x_bytes, "big")
        y = int.from_bytes(y_bytes, "big")
        if "d" in obj:
            try:
                d_bytes = base64url_decode(obj["d"])
            except Exception as exc:
                raise InvalidKeyError(str(exc)) from exc
            if len(d_bytes) > coord_len:
                raise InvalidKeyError(
                    f"EC private key length {len(d_bytes)} exceeds expected {coord_len} for {crv}"
                )
            private_value = int.from_bytes(d_bytes, "big")
            try:
                private_key = ec.derive_private_key(private_value, curve)
            except Exception as exc:
                raise InvalidKeyError(str(exc)) from exc
            derived = private_key.public_key().public_numbers()
            if derived.x != x or derived.y != y:
                raise InvalidKeyError("Invalid EC key")
            return private_key
        try:
            public_numbers = ec.EllipticCurvePublicNumbers(x=x, y=y, curve=curve)
            return public_numbers.public_key()
        except Exception as exc:
            raise InvalidKeyError(str(exc)) from exc


if has_crypto:
    ECAlgorithm.SHA256 = _hashes.SHA256()  # type: ignore[attr-defined]
    ECAlgorithm.SHA384 = _hashes.SHA384()  # type: ignore[attr-defined]
    ECAlgorithm.SHA512 = _hashes.SHA512()  # type: ignore[attr-defined]


class OKPAlgorithm(_RustBackedAlgorithm):
    def __init__(self) -> None:
        super().__init__("EdDSA")

    def prepare_key(self, key: Any) -> AllowedOKPKeys:
        if not has_crypto:
            raise InvalidKeyError("cryptography is required")
        if isinstance(key, (ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey,
                            ed448.Ed448PrivateKey, ed448.Ed448PublicKey)):
            return key
        if isinstance(key, (str, bytes)):
            key_bytes = force_bytes(key)
            key_str = key_bytes.decode("utf-8")
            try:
                if "-----BEGIN PUBLIC" in key_str:
                    loaded = serialization.load_pem_public_key(key_bytes)
                elif "-----BEGIN PRIVATE" in key_str:
                    loaded = serialization.load_pem_private_key(key_bytes, password=None)
                elif key_str.startswith("ssh-"):
                    loaded = serialization.load_ssh_public_key(key_bytes)
                else:
                    raise InvalidKeyError("Not a public or private key")
            except (ValueError, TypeError):
                raise InvalidKeyError("Not a public or private key") from None
        else:
            loaded = key
        if isinstance(loaded, (ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey)):
            return loaded
        if isinstance(loaded, (ed448.Ed448PrivateKey, ed448.Ed448PublicKey)):
            return loaded
        raise InvalidKeyError("Not a public or private key")

    @overload
    @staticmethod
    def to_jwk(key: Any, as_dict: Literal[True]) -> JWKDict: ...

    @overload
    @staticmethod
    def to_jwk(key: Any, as_dict: Literal[False] = False) -> str: ...

    @staticmethod
    def to_jwk(key: Any, as_dict: bool = False) -> JWKDict | str:
        if isinstance(key, (str, bytes)):
            key = OKPAlgorithm().prepare_key(key)
        if isinstance(key, ed25519.Ed25519PrivateKey):
            x = key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            d = key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            )
            obj = {
                "x": base64url_encode(x),
                "d": base64url_encode(d),
                "kty": "OKP",
                "crv": "Ed25519",
            }
        elif isinstance(key, ed25519.Ed25519PublicKey):
            x = key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            obj = {
                "x": base64url_encode(x),
                "kty": "OKP",
                "crv": "Ed25519",
            }
        elif isinstance(key, ed448.Ed448PrivateKey):
            x = key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            d = key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            )
            obj = {"x": base64url_encode(x), "d": base64url_encode(d), "kty": "OKP", "crv": "Ed448"}
        elif isinstance(key, ed448.Ed448PublicKey):
            x = key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            obj = {"x": base64url_encode(x), "kty": "OKP", "crv": "Ed448"}
        else:
            raise InvalidKeyError("Not a public or private key")
        return obj if as_dict else json.dumps(obj)

    def sign(self, msg: bytes, key: Any) -> bytes:
        if isinstance(key, ed448.Ed448PrivateKey):
            return key.sign(msg)
        return super().sign(msg, key)

    def verify(self, msg: bytes, key: Any, sig: bytes) -> bool:
        if isinstance(key, ed448.Ed448PublicKey):
            try:
                key.verify(sig, msg)
                return True
            except Exception:
                return False
        if isinstance(key, ed448.Ed448PrivateKey):
            try:
                key.public_key().verify(sig, msg)
                return True
            except Exception:
                return False
        if isinstance(key, ed25519.Ed25519PrivateKey):
            return super().verify(msg, key.public_key(), sig)
        return super().verify(msg, key, sig)

    @staticmethod
    def from_jwk(jwk: str | JWKDict) -> AllowedOKPKeys:
        try:
            obj = json.loads(jwk) if isinstance(jwk, str) else jwk
        except (ValueError, TypeError):
            raise InvalidKeyError("Key is not valid JSON") from None
        if not isinstance(obj, dict) or obj.get("kty") != "OKP":
            raise InvalidKeyError("Not an OKP key")
        crv = obj.get("crv")
        if crv == "Ed25519":
            try:
                if "d" in obj:
                    return ed25519.Ed25519PrivateKey.from_private_bytes(base64url_decode(obj["d"]))
                return ed25519.Ed25519PublicKey.from_public_bytes(base64url_decode(obj["x"]))
            except Exception as exc:
                raise InvalidKeyError(str(exc)) from exc
        elif crv == "Ed448":
            try:
                if "d" in obj:
                    return ed448.Ed448PrivateKey.from_private_bytes(base64url_decode(obj["d"]))
                return ed448.Ed448PublicKey.from_public_bytes(base64url_decode(obj["x"]))
            except Exception as exc:
                raise InvalidKeyError(str(exc)) from exc
        else:
            raise InvalidKeyError(f"Unsupported crv: {crv}")


def get_default_algorithms() -> dict[str, Algorithm]:
    algorithms: dict[str, Algorithm] = {
        "none": NoneAlgorithm(),
        "HS256": HMACAlgorithm(HMACAlgorithm.SHA256),
        "HS384": HMACAlgorithm(HMACAlgorithm.SHA384),
        "HS512": HMACAlgorithm(HMACAlgorithm.SHA512),
    }
    if has_crypto:
        algorithms.update(
            {
                "RS256": RSAAlgorithm(RSAAlgorithm.SHA256),
                "RS384": RSAAlgorithm(RSAAlgorithm.SHA384),
                "RS512": RSAAlgorithm(RSAAlgorithm.SHA512),
                "PS256": RSAPSSAlgorithm(RSAPSSAlgorithm.SHA256),
                "PS384": RSAPSSAlgorithm(RSAPSSAlgorithm.SHA384),
                "PS512": RSAPSSAlgorithm(RSAPSSAlgorithm.SHA512),
                "ES256": ECAlgorithm(ECAlgorithm.SHA256, ec.SECP256R1),
                "ES256K": ECAlgorithm(ECAlgorithm.SHA256, ec.SECP256K1),
                "ES384": ECAlgorithm(ECAlgorithm.SHA384, ec.SECP384R1),
                "ES521": ECAlgorithm(ECAlgorithm.SHA512, ec.SECP521R1),
                "ES512": ECAlgorithm(ECAlgorithm.SHA512, ec.SECP521R1),
                "EdDSA": OKPAlgorithm(),
            }
        )
    return algorithms
