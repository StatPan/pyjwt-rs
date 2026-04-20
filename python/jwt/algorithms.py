from __future__ import annotations

import hashlib
import hmac
import json
from abc import ABC, abstractmethod
from typing import Any, ClassVar, Literal, overload

from ._rust_pyjwt import (
    RustInvalidAlgorithmError,
    RustInvalidKeyError,
    RustJWTError,
    base64url_decode,
    base64url_encode,
    sign as rust_sign,
    verify as rust_verify,
)
from .exceptions import InvalidKeyError
from .types import HashlibHash, JWKDict

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, rsa

    has_crypto = True
except ModuleNotFoundError:
    has_crypto = False


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

    def __init__(self, name: str, hash_alg: HashlibHash) -> None:
        self.name = name
        self.hash_alg = hash_alg

    def prepare_key(self, key: str | bytes) -> bytes:
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
            return base64url_decode(rust_sign(msg, key, self.name))
        except RustInvalidAlgorithmError as exc:
            raise NotImplementedError("Algorithm not supported") from exc
        except RustInvalidKeyError as exc:
            raise InvalidKeyError(str(exc)) from exc
        except RustJWTError as exc:
            raise InvalidKeyError(str(exc)) from exc

    def verify(self, msg: bytes, key: bytes, sig: bytes) -> bool:
        try:
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

    @staticmethod
    def from_jwk(jwk: str | JWKDict) -> bytes:
        try:
            obj = json.loads(jwk) if isinstance(jwk, str) else jwk
        except ValueError:
            raise InvalidKeyError("Key is not valid JSON") from None
        if not isinstance(obj, dict) or obj.get("kty") != "oct":
            raise InvalidKeyError("Not an HMAC key")
        return base64url_decode(obj["k"])


class _RustBackedAlgorithm(Algorithm):
    def __init__(self, name: str) -> None:
        self.name = name

    def sign(self, msg: bytes, key: Any) -> bytes:
        try:
            return base64url_decode(rust_sign(msg, key, self.name))
        except RustInvalidAlgorithmError as exc:
            raise NotImplementedError("Algorithm not supported") from exc
        except RustInvalidKeyError as exc:
            raise InvalidKeyError(str(exc)) from exc
        except RustJWTError as exc:
            raise InvalidKeyError(str(exc)) from exc

    def verify(self, msg: bytes, key: Any, sig: bytes) -> bool:
        try:
            return rust_verify(base64url_encode(sig), msg, key, self.name)
        except RustInvalidAlgorithmError as exc:
            raise NotImplementedError("Algorithm not supported") from exc
        except RustInvalidKeyError as exc:
            raise InvalidKeyError(str(exc)) from exc
        except RustJWTError:
            return False


class RSAAlgorithm(_RustBackedAlgorithm):
    _MIN_KEY_SIZE: ClassVar[int] = 2048

    def prepare_key(self, key: Any) -> bytes:
        if not has_crypto:
            raise InvalidKeyError("cryptography is required")
        if isinstance(key, (str, bytes)):
            key_bytes = force_bytes(key)
            try:
                if key_bytes.startswith(b"ssh-rsa"):
                    loaded = serialization.load_ssh_public_key(key_bytes)
                    if not isinstance(loaded, rsa.RSAPublicKey):
                        raise InvalidKeyError("Expected an RSA key")
                    return _serialize_public_key(loaded)
                try:
                    loaded = serialization.load_pem_private_key(key_bytes, password=None)
                except ValueError:
                    loaded = serialization.load_pem_public_key(key_bytes)
                if isinstance(loaded, rsa.RSAPrivateKey):
                    return _serialize_private_key(loaded)
                if isinstance(loaded, rsa.RSAPublicKey):
                    return _serialize_public_key(loaded)
            except (ValueError, TypeError):
                raise InvalidKeyError("Could not parse the provided public key.") from None
            raise InvalidKeyError("Expected an RSA key")
        if isinstance(key, rsa.RSAPrivateKey):
            return _serialize_private_key(key)
        if isinstance(key, rsa.RSAPublicKey):
            return _serialize_public_key(key)
        raise TypeError("Expecting a PEM-formatted key.")

    def check_key_length(self, key: bytes) -> str | None:
        try:
            loaded = serialization.load_pem_private_key(key, password=None)
            key_size = loaded.key_size if isinstance(loaded, rsa.RSAPrivateKey) else None
        except ValueError:
            loaded = serialization.load_pem_public_key(key)
            key_size = loaded.key_size if isinstance(loaded, rsa.RSAPublicKey) else None
        if key_size is not None and key_size < self._MIN_KEY_SIZE:
            return (
                f"The RSA key is {key_size} bits long, which is below "
                f"the minimum recommended size of {self._MIN_KEY_SIZE} bits. "
                f"See NIST SP 800-131A."
            )
        return None

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
    def from_jwk(jwk: str | JWKDict) -> bytes:
        try:
            obj = json.loads(jwk) if isinstance(jwk, str) else jwk
        except ValueError:
            raise InvalidKeyError("Key is not valid JSON") from None
        if not isinstance(obj, dict) or obj.get("kty") != "RSA":
            raise InvalidKeyError("Not an RSA key")
        n = _b64u_to_int(obj["n"])
        e = _b64u_to_int(obj["e"])
        if "d" in obj:
            if "oth" in obj:
                raise InvalidKeyError("Unsupported RSA private key: > 2 primes not supported")
            public_numbers = rsa.RSAPublicNumbers(e=e, n=n)
            private_numbers = rsa.RSAPrivateNumbers(
                p=_b64u_to_int(obj["p"]),
                q=_b64u_to_int(obj["q"]),
                d=_b64u_to_int(obj["d"]),
                dmp1=_b64u_to_int(obj["dp"]),
                dmq1=_b64u_to_int(obj["dq"]),
                iqmp=_b64u_to_int(obj["qi"]),
                public_numbers=public_numbers,
            )
            return _serialize_private_key(private_numbers.private_key())
        return _serialize_public_key(rsa.RSAPublicNumbers(e=e, n=n).public_key())


class RSAPSSAlgorithm(RSAAlgorithm):
    pass


class ECAlgorithm(_RustBackedAlgorithm):
    def __init__(self, name: str, curve_name: str, expected_curve: type[Any]) -> None:
        super().__init__(name)
        self.curve_name = curve_name
        self.expected_curve = expected_curve

    def _validate_curve(self, key: Any) -> None:
        if not isinstance(key.curve, self.expected_curve):
            raise InvalidKeyError(
                f"The key's curve '{key.curve.name}' does not match the expected curve "
                f"'{self.expected_curve.name}' for this algorithm"
            )

    def prepare_key(self, key: Any) -> bytes:
        if not has_crypto:
            raise InvalidKeyError("cryptography is required")
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
            return _serialize_private_key(loaded)
        if isinstance(loaded, ec.EllipticCurvePublicKey):
            self._validate_curve(loaded)
            return _serialize_public_key(loaded)
        raise InvalidKeyError("Expecting a PEM-formatted key.")

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
        obj["key_ops"] = ["sign"] if private_value is not None else ["verify"]
        if private_value is not None:
            obj["d"] = _int_to_b64u(private_value)
        return obj if as_dict else json.dumps(obj)

    @staticmethod
    def from_jwk(jwk: str | JWKDict) -> bytes:
        try:
            obj = json.loads(jwk) if isinstance(jwk, str) else jwk
        except ValueError:
            raise InvalidKeyError("Key is not valid JSON") from None
        if not isinstance(obj, dict) or obj.get("kty") != "EC":
            raise InvalidKeyError("Not an EC key")
        curve_map = {
            "P-256": ec.SECP256R1(),
            "P-384": ec.SECP384R1(),
            "P-521": ec.SECP521R1(),
            "secp256k1": ec.SECP256K1(),
        }
        curve = curve_map.get(obj.get("crv"))
        if curve is None:
            raise InvalidKeyError(f"Invalid curve: {obj.get('crv')}")
        x = _b64u_to_int(obj["x"])
        y = _b64u_to_int(obj["y"])
        if "d" in obj:
            private_value = _b64u_to_int(obj["d"])
            private_key = ec.derive_private_key(private_value, curve)
            derived = private_key.public_key().public_numbers()
            if derived.x != x or derived.y != y:
                raise InvalidKeyError("Invalid EC key")
            return _serialize_private_key(private_key)
        public_numbers = ec.EllipticCurvePublicNumbers(x=x, y=y, curve=curve)
        return _serialize_public_key(public_numbers.public_key())


class OKPAlgorithm(_RustBackedAlgorithm):
    def prepare_key(self, key: Any) -> bytes:
        if not has_crypto:
            raise InvalidKeyError("cryptography is required")
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
        if isinstance(loaded, ed25519.Ed25519PrivateKey):
            return _serialize_private_key(loaded)
        if isinstance(loaded, ed25519.Ed25519PublicKey):
            return _serialize_public_key(loaded)
        if has_crypto and isinstance(loaded, (ed448.Ed448PrivateKey, ed448.Ed448PublicKey)):
            raise InvalidKeyError("Unsupported OKP curve: Ed448")
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
            prepared = OKPAlgorithm("EdDSA").prepare_key(key)
            key_bytes = force_bytes(prepared)
            try:
                key = serialization.load_pem_private_key(key_bytes, password=None)
            except ValueError:
                key = serialization.load_pem_public_key(key_bytes)
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
        else:
            raise InvalidKeyError("Not a public or private key")
        return obj if as_dict else json.dumps(obj)

    @staticmethod
    def from_jwk(jwk: str | JWKDict) -> bytes:
        try:
            obj = json.loads(jwk) if isinstance(jwk, str) else jwk
        except ValueError:
            raise InvalidKeyError("Key is not valid JSON") from None
        if not isinstance(obj, dict) or obj.get("kty") != "OKP":
            raise InvalidKeyError("Not an OKP key")
        if obj.get("crv") != "Ed25519":
            raise InvalidKeyError(f"Unsupported crv: {obj.get('crv')}")
        if "d" in obj:
            key = ed25519.Ed25519PrivateKey.from_private_bytes(base64url_decode(obj["d"]))
            return _serialize_private_key(key)
        key = ed25519.Ed25519PublicKey.from_public_bytes(base64url_decode(obj["x"]))
        return _serialize_public_key(key)


def get_default_algorithms() -> dict[str, Algorithm]:
    algorithms: dict[str, Algorithm] = {
        "none": NoneAlgorithm(),
        "HS256": HMACAlgorithm("HS256", HMACAlgorithm.SHA256),
        "HS384": HMACAlgorithm("HS384", HMACAlgorithm.SHA384),
        "HS512": HMACAlgorithm("HS512", HMACAlgorithm.SHA512),
    }
    if has_crypto:
        algorithms.update(
            {
                "RS256": RSAAlgorithm("RS256"),
                "RS384": RSAAlgorithm("RS384"),
                "RS512": RSAAlgorithm("RS512"),
                "PS256": RSAPSSAlgorithm("PS256"),
                "PS384": RSAPSSAlgorithm("PS384"),
                "PS512": RSAPSSAlgorithm("PS512"),
                "ES256": ECAlgorithm("ES256", "P-256", ec.SECP256R1),
                "ES256K": ECAlgorithm("ES256K", "secp256k1", ec.SECP256K1),
                "ES384": ECAlgorithm("ES384", "P-384", ec.SECP384R1),
                "ES521": ECAlgorithm("ES512", "P-521", ec.SECP521R1),
                "ES512": ECAlgorithm("ES512", "P-521", ec.SECP521R1),
                "EdDSA": OKPAlgorithm("EdDSA"),
            }
        )
    return algorithms
