from __future__ import annotations

import json
import time
from collections.abc import Iterator
from typing import Any

from .algorithms import get_default_algorithms, has_crypto, requires_cryptography
from .exceptions import InvalidKeyError, MissingCryptographyError, PyJWKError, PyJWKSetError


class PyJWK:
    def __init__(self, jwk_data: dict[str, Any], algorithm: str | None = None) -> None:
        self._jwk_data = jwk_data

        kty = self._jwk_data.get("kty", None)
        if not kty:
            raise InvalidKeyError(f"kty is not found: {self._jwk_data}")

        if not algorithm and isinstance(self._jwk_data, dict):
            algorithm = self._jwk_data.get("alg", None)

        if not algorithm:
            crv = self._jwk_data.get("crv", None)
            if kty == "EC":
                if crv == "P-256" or not crv:
                    algorithm = "ES256"
                elif crv == "P-384":
                    algorithm = "ES384"
                elif crv == "P-521":
                    algorithm = "ES512"
                elif crv == "secp256k1":
                    algorithm = "ES256K"
                else:
                    raise InvalidKeyError(f"Unsupported crv: {crv}")
            elif kty == "RSA":
                algorithm = "RS256"
            elif kty == "oct":
                algorithm = "HS256"
            elif kty == "OKP":
                if not crv:
                    raise InvalidKeyError(f"crv is not found: {self._jwk_data}")
                if crv == "Ed25519":
                    algorithm = "EdDSA"
                else:
                    raise InvalidKeyError(f"Unsupported crv: {crv}")
            else:
                raise InvalidKeyError(f"Unsupported kty: {kty}")

        self.algorithm_name = algorithm
        if not has_crypto and algorithm in requires_cryptography:
            raise MissingCryptographyError(f"{algorithm} requires 'cryptography' to be installed.")

        try:
            self.Algorithm = get_default_algorithms()[algorithm]
        except KeyError:
            raise PyJWKError(f"Unable to find an algorithm for key: {self._jwk_data}") from None

        try:
            self.key = self.Algorithm.from_jwk(self._jwk_data)
        except InvalidKeyError:
            raise
        except Exception as exc:
            raise PyJWKError(f"Unable to find an algorithm for key: {self._jwk_data}") from exc

    @staticmethod
    def from_dict(obj: dict[str, Any], algorithm: str | None = None) -> "PyJWK":
        return PyJWK(obj, algorithm)

    @staticmethod
    def from_json(data: str, algorithm: str | None = None) -> "PyJWK":
        obj = json.loads(data)
        return PyJWK.from_dict(obj, algorithm)

    @property
    def key_type(self) -> str | None:
        return self._jwk_data.get("kty", None)

    @property
    def key_id(self) -> str | None:
        return self._jwk_data.get("kid", None)

    @property
    def public_key_use(self) -> str | None:
        return self._jwk_data.get("use", None)


class PyJWKSet:
    def __init__(self, keys: list[dict[str, Any]]) -> None:
        self.keys: list[PyJWK] = []

        if not keys:
            raise PyJWKSetError("The JWK Set did not contain any keys")

        if not isinstance(keys, list):
            raise PyJWKSetError("Invalid JWK Set value")

        for key in keys:
            try:
                self.keys.append(PyJWK(key))
            except PyJWKError:
                continue
            except InvalidKeyError:
                continue

        if len(self.keys) == 0:
            raise PyJWKSetError(
                "The JWK Set did not contain any usable keys. Perhaps 'cryptography' is not installed?"
            )

    @staticmethod
    def from_dict(obj: dict[str, Any]) -> "PyJWKSet":
        keys = obj.get("keys", [])
        return PyJWKSet(keys)

    @staticmethod
    def from_json(data: str) -> "PyJWKSet":
        obj = json.loads(data)
        return PyJWKSet.from_dict(obj)

    def __getitem__(self, kid: str) -> PyJWK:
        for key in self.keys:
            if key.key_id == kid:
                return key
        raise KeyError(f"keyset has no key for kid: {kid}")

    def __iter__(self) -> Iterator[PyJWK]:
        return iter(self.keys)


class PyJWTSetWithTimestamp:
    def __init__(self, jwk_set: PyJWKSet):
        self.jwk_set = jwk_set
        self.timestamp = time.monotonic()

    def get_jwk_set(self) -> PyJWKSet:
        return self.jwk_set

    def get_timestamp(self) -> float:
        return self.timestamp
