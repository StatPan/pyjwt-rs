from __future__ import annotations

import binascii
import json
import warnings
from collections.abc import Sequence
from typing import Any

from ._rust_pyjwt import RustJWTError, base64url_decode, base64url_encode
from .algorithms import Algorithm, get_default_algorithms, has_crypto, requires_cryptography

from .exceptions import (
    DecodeError,
    InvalidAlgorithmError,
    InvalidKeyError,
    InvalidSignatureError,
    InvalidTokenError,
)
from .api_jwk import PyJWK
from .warnings import InsecureKeyLengthWarning, RemovedInPyjwt3Warning

_ALGORITHM_UNSET = object()
class PyJWS:
    header_typ = "JWT"

    def __init__(
        self,
        algorithms: Sequence[str] | None = None,
        options: dict[str, Any] | None = None,
    ) -> None:
        self._algorithms = get_default_algorithms()
        self._valid_algs = set(algorithms) if algorithms is not None else set(self._algorithms)
        for key in list(self._algorithms.keys()):
            if key not in self._valid_algs:
                del self._algorithms[key]
        self.options = self._get_default_options()
        if options is not None:
            self.options = {**self.options, **options}

    @staticmethod
    def _get_default_options() -> dict[str, Any]:
        return {"verify_signature": True, "enforce_minimum_key_length": False}

    def register_algorithm(self, alg_id: str, alg_obj: Any) -> None:
        if alg_id in self._algorithms:
            raise ValueError("Algorithm already has a handler.")
        if not isinstance(alg_obj, Algorithm):
            raise TypeError("Object is not of type `Algorithm`")
        self._algorithms[alg_id] = alg_obj
        self._valid_algs.add(alg_id)

    def unregister_algorithm(self, alg_id: str) -> None:
        if alg_id not in self._algorithms:
            raise KeyError(
                "The specified algorithm could not be removed because it is not registered."
            )
        del self._algorithms[alg_id]
        self._valid_algs.discard(alg_id)

    def get_algorithms(self) -> list[str]:
        return list(self._valid_algs)

    def get_algorithm_by_name(self, alg_name: str) -> Algorithm:
        try:
            return self._algorithms[alg_name]
        except KeyError as exc:
            if not has_crypto and alg_name in requires_cryptography:
                raise NotImplementedError(
                    f"Algorithm '{alg_name}' could not be found. Do you have cryptography installed?"
                ) from exc
            raise NotImplementedError("Algorithm not supported") from exc

    def encode(
        self,
        payload: bytes,
        key: Any,
        algorithm: str | None = _ALGORITHM_UNSET,
        headers: dict[str, Any] | None = None,
        json_encoder: type[json.JSONEncoder] | None = None,
        is_payload_detached: bool = False,
        sort_headers: bool = True,
    ) -> str:
        if algorithm is _ALGORITHM_UNSET:
            if isinstance(key, PyJWK):
                algorithm_ = key.algorithm_name
            else:
                algorithm_ = "HS256"
        elif algorithm is None:
            if isinstance(key, PyJWK):
                algorithm_ = key.algorithm_name
            else:
                algorithm_ = "none"
        else:
            algorithm_ = algorithm

        if headers:
            headers_alg = headers.get("alg")
            if headers_alg:
                algorithm_ = headers_alg

            headers_b64 = headers.get("b64")
            if headers_b64 is False:
                is_payload_detached = True

        header: dict[str, Any] = {"typ": self.header_typ, "alg": algorithm_}

        if headers:
            self._validate_headers(headers, encoding=True)
            header.update(headers)

        if not header["typ"]:
            del header["typ"]

        if is_payload_detached:
            header["b64"] = False
        elif "b64" in header:
            del header["b64"]

        json_header = json.dumps(
            header, separators=(",", ":"), cls=json_encoder, sort_keys=sort_headers
        ).encode()
        encoded_header = base64url_encode(json_header)

        if is_payload_detached:
            payload_segment = payload.decode("utf-8")
            msg_payload = payload
        else:
            payload_segment = base64url_encode(payload)
            msg_payload = payload_segment.encode("ascii")

        signing_input = encoded_header.encode("ascii") + b"." + msg_payload

        alg_obj = self.get_algorithm_by_name(algorithm_)
        raw_key = key.key if isinstance(key, PyJWK) else key
        prepared_key = alg_obj.prepare_key(raw_key)

        key_length_msg = alg_obj.check_key_length(prepared_key)
        if key_length_msg:
            if self.options.get("enforce_minimum_key_length", False):
                raise InvalidKeyError(key_length_msg)
            warnings.warn(key_length_msg, InsecureKeyLengthWarning, stacklevel=2)

        try:
            signature = base64url_encode(alg_obj.sign(signing_input, prepared_key))
        except RustJWTError as exc:
            raise InvalidTokenError(str(exc)) from exc

        if is_payload_detached:
            payload_segment = ""

        return f"{encoded_header}.{payload_segment}.{signature}"

    def decode_complete(
        self,
        jwt: str | bytes,
        key: Any = "",
        algorithms: Sequence[str] | None = None,
        options: dict[str, Any] | None = None,
        detached_payload: bytes | None = None,
        **kwargs: dict[str, Any],
    ) -> dict[str, Any]:
        if kwargs:
            warnings.warn(
                "passing additional kwargs to decode_complete() is deprecated "
                "and will be removed in pyjwt version 3. "
                f"Unsupported kwargs: {tuple(kwargs.keys())}",
                RemovedInPyjwt3Warning,
                stacklevel=2,
            )
        merged_options = self.options if options is None else {**self.options, **options}
        verify_signature = merged_options["verify_signature"]

        if verify_signature and not algorithms and not isinstance(key, PyJWK):
            raise DecodeError(
                'It is required that you pass in a value for the "algorithms" argument when calling decode().'
            )

        payload, signing_input, header, signature = self._load(jwt)
        self._validate_headers(header)

        if header.get("b64", True) is False:
            if detached_payload is None:
                raise DecodeError(
                    'It is required that you pass in a value for the "detached_payload" argument to decode a message having the b64 header set to false.'
                )
            payload = detached_payload
            signing_input = b".".join([signing_input.rsplit(b".", 1)[0], payload])

        if verify_signature:
            self._verify_signature(signing_input, header, signature, key, algorithms)

        return {"payload": payload, "header": header, "signature": signature}

    def decode(
        self,
        jwt: str | bytes,
        key: Any = "",
        algorithms: Sequence[str] | None = None,
        options: dict[str, Any] | None = None,
        detached_payload: bytes | None = None,
        **kwargs: dict[str, Any],
    ) -> Any:
        if kwargs:
            warnings.warn(
                "passing additional kwargs to decode() is deprecated "
                "and will be removed in pyjwt version 3. "
                f"Unsupported kwargs: {tuple(kwargs.keys())}",
                RemovedInPyjwt3Warning,
                stacklevel=2,
            )
        decoded = self.decode_complete(
            jwt, key, algorithms, options, detached_payload=detached_payload
        )
        return decoded["payload"]

    def get_unverified_header(self, jwt: str | bytes) -> dict[str, Any]:
        headers = self._load(jwt)[2]
        self._validate_headers(headers)
        return headers

    def _load(self, jwt: str | bytes) -> tuple[bytes, bytes, dict[str, Any], bytes]:
        if isinstance(jwt, str):
            jwt = jwt.encode("utf-8")

        if not isinstance(jwt, bytes):
            raise DecodeError(f"Invalid token type. Token must be a {bytes}")

        try:
            signing_input, crypto_segment = jwt.rsplit(b".", 1)
            header_segment, payload_segment = signing_input.split(b".", 1)
        except ValueError as err:
            raise DecodeError("Not enough segments") from err

        try:
            header_data = base64url_decode(header_segment.decode("ascii"))
        except (TypeError, ValueError, binascii.Error, RustJWTError) as err:
            raise DecodeError("Invalid header padding") from err

        try:
            header: dict[str, Any] = json.loads(header_data)
        except ValueError as err:
            raise DecodeError(f"Invalid header string: {err}") from err

        if not isinstance(header, dict):
            raise DecodeError("Invalid header string: must be a json object")

        try:
            payload = base64url_decode(payload_segment.decode("ascii"))
        except (TypeError, ValueError, binascii.Error, RustJWTError) as err:
            raise DecodeError("Invalid payload padding") from err

        try:
            signature = base64url_decode(crypto_segment.decode("ascii"))
        except (TypeError, ValueError, binascii.Error, RustJWTError) as err:
            raise DecodeError("Invalid crypto padding") from err

        return payload, signing_input, header, signature

    def _verify_signature(
        self,
        signing_input: bytes,
        header: dict[str, Any],
        signature: bytes,
        key: Any = "",
        algorithms: Sequence[str] | None = None,
    ) -> None:
        try:
            alg = header["alg"]
        except KeyError:
            raise InvalidAlgorithmError("Algorithm not specified") from None

        if algorithms is None and isinstance(key, PyJWK):
            algorithms = [key.algorithm_name]

        if not alg or (algorithms is not None and alg not in algorithms):
            raise InvalidAlgorithmError("The specified alg value is not allowed")

        if isinstance(key, PyJWK):
            alg_obj = key.Algorithm
            prepared_key = alg_obj.prepare_key(key.key)
        else:
            try:
                alg_obj = self.get_algorithm_by_name(alg)
            except NotImplementedError as exc:
                raise InvalidAlgorithmError("Algorithm not supported") from exc
            prepared_key = alg_obj.prepare_key(key)

        key_length_msg = alg_obj.check_key_length(prepared_key)
        if key_length_msg:
            if self.options.get("enforce_minimum_key_length", False):
                raise InvalidKeyError(key_length_msg)
            warnings.warn(key_length_msg, InsecureKeyLengthWarning, stacklevel=4)

        try:
            ok = alg_obj.verify(signing_input, prepared_key, signature)
        except RustJWTError as exc:
            raise InvalidTokenError(str(exc)) from exc

        if not ok:
            raise InvalidSignatureError("Signature verification failed")

    _supported_crit: set[str] = {"b64"}

    def _validate_headers(self, headers: dict[str, Any], *, encoding: bool = False) -> None:
        if "kid" in headers:
            self._validate_kid(headers["kid"])
        if not encoding and "crit" in headers:
            self._validate_crit(headers)

    def _validate_kid(self, kid: Any) -> None:
        if not isinstance(kid, str):
            raise InvalidTokenError("Key ID header parameter must be a string")

    def _validate_crit(self, headers: dict[str, Any]) -> None:
        crit = headers["crit"]
        if not isinstance(crit, list) or len(crit) == 0:
            raise InvalidTokenError("Invalid 'crit' header: must be a non-empty list")
        for ext in crit:
            if not isinstance(ext, str):
                raise InvalidTokenError("Invalid 'crit' header: values must be strings")
            if ext not in self._supported_crit:
                raise InvalidTokenError(f"Unsupported critical extension: {ext}")
            if ext not in headers:
                raise InvalidTokenError(f"Critical extension '{ext}' is missing from headers")


_jws_global_obj = PyJWS()
encode = _jws_global_obj.encode
decode_complete = _jws_global_obj.decode_complete
decode = _jws_global_obj.decode
register_algorithm = _jws_global_obj.register_algorithm
unregister_algorithm = _jws_global_obj.unregister_algorithm
get_algorithm_by_name = _jws_global_obj.get_algorithm_by_name
get_unverified_header = _jws_global_obj.get_unverified_header
