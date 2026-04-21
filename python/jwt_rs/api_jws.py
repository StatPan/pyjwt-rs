from __future__ import annotations

import binascii
import json
import warnings
from collections.abc import Sequence
from typing import Any

from ._rust_pyjwt import (
    RustJWTError,
    RustKeyHandle,
    base64url_decode,
    base64url_encode,
    decode_and_verify as rust_decode_and_verify,
    decode_segments as rust_decode_segments,
    encode_token as rust_encode_token,
    sign_prepared as rust_sign_prepared,
    sign_prepared_raw as rust_sign_prepared_raw,
    verify_prepared as rust_verify_prepared,
    verify_prepared_raw as rust_verify_prepared_raw,
)
from .algorithms import (
    Algorithm,
    HMACAlgorithm,
    get_default_algorithms,
    has_crypto,
    prepare_rust_handle,
    requires_cryptography,
)

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
_DEFAULT_HEADER_B64_CACHE: dict[str, str] = {}


def _default_header_b64(algorithm: str, typ: str) -> str:
    cache_key = f"{typ}:{algorithm}" if typ else f":{algorithm}"
    cached = _DEFAULT_HEADER_B64_CACHE.get(cache_key)
    if cached is not None:
        return cached
    header: dict[str, Any] = {"alg": algorithm}
    if typ:
        header["typ"] = typ
    # sort_keys=True matches default sort_headers=True behavior; "alg" < "typ".
    json_bytes = json.dumps(header, separators=(",", ":"), sort_keys=True).encode()
    encoded = base64url_encode(json_bytes)
    _DEFAULT_HEADER_B64_CACHE[cache_key] = encoded
    return encoded


_RUST_PREPARED_ALGORITHMS = {
    "HS256",
    "HS384",
    "HS512",
    "RS256",
    "RS384",
    "RS512",
    "PS256",
    "PS384",
    "PS512",
    "ES256",
    "ES256K",
    "ES384",
    "ES512",
    "EdDSA",
}

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

        if (
            not headers
            and not is_payload_detached
            and json_encoder is None
            and sort_headers
        ):
            encoded_header = _default_header_b64(algorithm_, self.header_typ)
        else:
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

        alg_obj = self.get_algorithm_by_name(algorithm_)
        raw_key = key.key if isinstance(key, PyJWK) else key
        prepared_handle = None
        if isinstance(key, PyJWK):
            prepared_handle = getattr(key, "_rust_encode_handle", None)
        elif algorithm_ in _RUST_PREPARED_ALGORITHMS:
            prepared_handle = prepare_rust_handle(raw_key, algorithm_, "encode")

        prepared_key = prepared_handle
        key_length_input = prepared_key
        if prepared_key is None or isinstance(alg_obj, HMACAlgorithm):
            prepared_key = alg_obj.prepare_key(raw_key)
            key_length_input = prepared_key
        elif isinstance(key, PyJWK) and isinstance(alg_obj, HMACAlgorithm):
            key_length_input = alg_obj.prepare_key(key.key)

        key_length_msg = alg_obj.check_key_length(key_length_input)
        if key_length_msg:
            if self.options.get("enforce_minimum_key_length", False):
                raise InvalidKeyError(key_length_msg)
            warnings.warn(key_length_msg, InsecureKeyLengthWarning, stacklevel=2)

        # Fast path: handle-based sign with full assembly in Rust.
        if isinstance(prepared_handle, RustKeyHandle):
            try:
                return rust_encode_token(
                    encoded_header, payload, prepared_handle, algorithm_, is_payload_detached
                )
            except RustJWTError as exc:
                raise InvalidTokenError(str(exc)) from exc

        if is_payload_detached:
            payload_segment = payload.decode("utf-8")
            msg_payload = payload
        else:
            payload_segment = base64url_encode(payload)
            msg_payload = payload_segment.encode("ascii")

        signing_input = encoded_header.encode("ascii") + b"." + msg_payload

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

        # Fast path: single-algorithm non-PyJWK decode+verify in one FFI call.
        if (
            verify_signature
            and detached_payload is None
            and not isinstance(key, PyJWK)
            and algorithms is not None
            and len(algorithms) == 1
            and isinstance(jwt, (str, bytes))
        ):
            alg_name = algorithms[0]
            if alg_name in _RUST_PREPARED_ALGORITHMS and not merged_options.get(
                "enforce_minimum_key_length", False
            ):
                handle = prepare_rust_handle(key, alg_name, "decode")
                if handle is not None:
                    try:
                        header_data, payload, signature, ok = rust_decode_and_verify(
                            jwt, handle, alg_name
                        )
                    except RustJWTError as err:
                        raise DecodeError(str(err)) from err
                    try:
                        header = json.loads(header_data)
                    except ValueError as err:
                        raise DecodeError(f"Invalid header string: {err}") from err
                    if not isinstance(header, dict):
                        raise DecodeError("Invalid header string: must be a json object")
                    self._validate_headers(header)
                    if header.get("b64", True) is False:
                        raise DecodeError(
                            'It is required that you pass in a value for the "detached_payload" argument to decode a message having the b64 header set to false.'
                        )
                    if header.get("alg") != alg_name:
                        raise InvalidAlgorithmError(
                            "The specified alg value is not allowed"
                        )
                    if not ok:
                        raise InvalidSignatureError("Signature verification failed")
                    return {"payload": payload, "header": header, "signature": signature}

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
        if not isinstance(jwt, (str, bytes)):
            raise DecodeError(f"Invalid token type. Token must be a {bytes}")

        try:
            payload, signing_input, header_data, signature = rust_decode_segments(jwt)
        except RustJWTError as err:
            raise DecodeError(str(err)) from err
        except (TypeError, ValueError, binascii.Error) as err:
            raise DecodeError("Not enough segments") from err

        try:
            header: dict[str, Any] = json.loads(header_data)
        except ValueError as err:
            raise DecodeError(f"Invalid header string: {err}") from err

        if not isinstance(header, dict):
            raise DecodeError("Invalid header string: must be a json object")

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
            prepared_key = getattr(key, "_rust_decode_handle", None)
            key_length_input = alg_obj.prepare_key(key.key) if isinstance(alg_obj, HMACAlgorithm) else prepared_key
            if prepared_key is None or isinstance(alg_obj, HMACAlgorithm):
                prepared_key = alg_obj.prepare_key(key.key)
                key_length_input = prepared_key
        else:
            try:
                alg_obj = self.get_algorithm_by_name(alg)
            except NotImplementedError as exc:
                raise InvalidAlgorithmError("Algorithm not supported") from exc
            prepared_key = None
            if alg in _RUST_PREPARED_ALGORITHMS:
                prepared_key = prepare_rust_handle(key, alg, "decode")
            key_length_input = prepared_key
            if prepared_key is None or isinstance(alg_obj, HMACAlgorithm):
                prepared_key = alg_obj.prepare_key(key)
                key_length_input = prepared_key

        key_length_msg = alg_obj.check_key_length(key_length_input)
        if key_length_msg:
            if self.options.get("enforce_minimum_key_length", False):
                raise InvalidKeyError(key_length_msg)
            warnings.warn(key_length_msg, InsecureKeyLengthWarning, stacklevel=4)

        try:
            if (
                isinstance(prepared_key, RustKeyHandle)
                and alg in _RUST_PREPARED_ALGORITHMS
            ):
                ok = rust_verify_prepared_raw(signature, signing_input, prepared_key, alg)
            else:
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
