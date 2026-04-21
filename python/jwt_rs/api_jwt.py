from __future__ import annotations

import json
import time
import warnings
from calendar import timegm
from collections.abc import Container, Iterable, Sequence
from datetime import datetime, timedelta, timezone
from typing import Any, cast

from .api_jws import _ALGORITHM_UNSET, PyJWS, _jws_global_obj
from .exceptions import (
    DecodeError,
    ExpiredSignatureError,
    ImmatureSignatureError,
    InvalidAudienceError,
    InvalidIssuedAtError,
    InvalidIssuerError,
    InvalidJTIError,
    InvalidSubjectError,
    MissingRequiredClaimError,
)
from .warnings import RemovedInPyjwt3Warning


class PyJWT:
    def __init__(self, options: dict[str, Any] | None = None) -> None:
        self.options = self._get_default_options()
        if options is not None:
            self.options = self._merge_options(options)
        self._jws = PyJWS(options=self._get_sig_options())

    @staticmethod
    def _get_default_options() -> dict[str, Any]:
        return {
            "verify_signature": True,
            "verify_exp": True,
            "verify_nbf": True,
            "verify_iat": True,
            "verify_aud": True,
            "verify_iss": True,
            "verify_sub": True,
            "verify_jti": True,
            "require": [],
            "strict_aud": False,
            "enforce_minimum_key_length": False,
        }

    def _get_sig_options(self) -> dict[str, Any]:
        return {
            "verify_signature": self.options["verify_signature"],
            "enforce_minimum_key_length": self.options.get(
                "enforce_minimum_key_length", False
            ),
        }

    def _merge_options(self, options: dict[str, Any] | None = None) -> dict[str, Any]:
        if options is None:
            return self.options

        if not options.get("verify_signature", True):
            options["verify_exp"] = options.get("verify_exp", False)
            options["verify_nbf"] = options.get("verify_nbf", False)
            options["verify_iat"] = options.get("verify_iat", False)
            options["verify_aud"] = options.get("verify_aud", False)
            options["verify_iss"] = options.get("verify_iss", False)
            options["verify_sub"] = options.get("verify_sub", False)
            options["verify_jti"] = options.get("verify_jti", False)
        return {**self.options, **options}

    def encode(
        self,
        payload: dict[str, Any],
        key: Any,
        algorithm: str | None = _ALGORITHM_UNSET,
        headers: dict[str, Any] | None = None,
        json_encoder: type[json.JSONEncoder] | None = None,
        sort_headers: bool = True,
    ) -> str:
        if not isinstance(payload, dict):
            raise TypeError(
                "Expecting a dict object, as JWT only supports JSON objects as payloads."
            )

        if (
            isinstance(payload.get("exp"), datetime)
            or isinstance(payload.get("iat"), datetime)
            or isinstance(payload.get("nbf"), datetime)
        ):
            payload = payload.copy()
            for time_claim in ("exp", "iat", "nbf"):
                value = payload.get(time_claim)
                if isinstance(value, datetime):
                    payload[time_claim] = timegm(value.utctimetuple())

        if "iss" in payload and not isinstance(payload["iss"], str):
            raise TypeError("Issuer (iss) must be a string.")

        json_payload = self._encode_payload(
            payload,
            headers=headers,
            json_encoder=json_encoder,
        )

        return self._jws.encode(
            json_payload,
            key,
            algorithm,
            headers,
            json_encoder,
            sort_headers=sort_headers,
        )

    def _encode_payload(
        self,
        payload: dict[str, Any],
        headers: dict[str, Any] | None = None,
        json_encoder: type[json.JSONEncoder] | None = None,
    ) -> bytes:
        return json.dumps(
            payload,
            separators=(",", ":"),
            cls=json_encoder,
        ).encode("utf-8")

    def decode_complete(
        self,
        jwt: str | bytes,
        key: Any = "",
        algorithms: Sequence[str] | None = None,
        options: dict[str, Any] | None = None,
        verify: bool | None = None,
        detached_payload: bytes | None = None,
        audience: str | Iterable[str] | None = None,
        issuer: str | Container[str] | None = None,
        subject: str | None = None,
        leeway: float | timedelta = 0,
        **kwargs: Any,
    ) -> dict[str, Any]:
        if kwargs:
            warnings.warn(
                "passing additional kwargs to decode_complete() is deprecated "
                "and will be removed in pyjwt version 3. "
                f"Unsupported kwargs: {tuple(kwargs.keys())}",
                RemovedInPyjwt3Warning,
                stacklevel=2,
            )

        if options is None:
            verify_signature = True
            merged_options = self.options
            sig_options = None
        else:
            verify_signature = options.get("verify_signature", True)
            merged_options = self._merge_options(options)
            sig_options = {"verify_signature": verify_signature}
            if "enforce_minimum_key_length" in merged_options:
                sig_options["enforce_minimum_key_length"] = merged_options[
                    "enforce_minimum_key_length"
                ]

        if verify is not None and verify != verify_signature:
            warnings.warn(
                "The `verify` argument to `decode` does nothing in PyJWT 2.0 and newer. "
                "The equivalent is setting `verify_signature` to False in the `options` dictionary. "
                "This invocation has a mismatch between the kwarg and the option entry.",
                category=DeprecationWarning,
                stacklevel=2,
            )

        decoded = self._jws.decode_complete(
            jwt,
            key=key,
            algorithms=algorithms,
            options=sig_options,
            detached_payload=detached_payload,
        )

        payload = self._decode_payload(decoded)

        self._validate_claims(
            payload,
            merged_options,
            audience=audience,
            issuer=issuer,
            leeway=leeway,
            subject=subject,
        )

        decoded["payload"] = payload
        return decoded

    def _decode_payload(self, decoded: dict[str, Any]) -> dict[str, Any]:
        try:
            payload: dict[str, Any] = json.loads(decoded["payload"])
        except ValueError as exc:
            raise DecodeError(f"Invalid payload string: {exc}") from exc
        if not isinstance(payload, dict):
            raise DecodeError("Invalid payload string: must be a json object")
        return payload

    def decode(
        self,
        jwt: str | bytes,
        key: Any = "",
        algorithms: Sequence[str] | None = None,
        options: dict[str, Any] | None = None,
        verify: bool | None = None,
        detached_payload: bytes | None = None,
        audience: str | Iterable[str] | None = None,
        subject: str | None = None,
        issuer: str | Container[str] | None = None,
        leeway: float | timedelta = 0,
        **kwargs: Any,
    ) -> dict[str, Any]:
        if kwargs:
            warnings.warn(
                "passing additional kwargs to decode() is deprecated "
                "and will be removed in pyjwt version 3. "
                f"Unsupported kwargs: {tuple(kwargs.keys())}",
                RemovedInPyjwt3Warning,
                stacklevel=2,
            )
        decoded = self.decode_complete(
            jwt,
            key,
            algorithms,
            options,
            verify=verify,
            detached_payload=detached_payload,
            audience=audience,
            subject=subject,
            issuer=issuer,
            leeway=leeway,
        )
        return cast(dict[str, Any], decoded["payload"])

    def _validate_claims(
        self,
        payload: dict[str, Any],
        options: dict[str, Any],
        audience: Iterable[str] | str | None = None,
        issuer: Container[str] | str | None = None,
        subject: str | None = None,
        leeway: float | timedelta = 0,
    ) -> None:
        if isinstance(leeway, timedelta):
            leeway = leeway.total_seconds()

        if audience is not None and not isinstance(audience, (str, Iterable)):
            raise TypeError("audience must be a string, iterable or None")

        required_claims = options["require"]
        if required_claims:
            self._validate_required_claims(payload, required_claims)

        now: float | None = None

        if options["verify_iat"] and "iat" in payload:
            now = time.time()
            self._validate_iat(payload, now, leeway)

        if options["verify_nbf"] and "nbf" in payload:
            if now is None:
                now = time.time()
            self._validate_nbf(payload, now, leeway)

        if options["verify_exp"] and "exp" in payload:
            if now is None:
                now = time.time()
            self._validate_exp(payload, now, leeway)

        if options["verify_iss"]:
            self._validate_iss(payload, issuer)

        if options["verify_aud"]:
            self._validate_aud(payload, audience, strict=options.get("strict_aud", False))

        if options["verify_sub"] and "sub" in payload:
            self._validate_sub(payload, subject)

        if options["verify_jti"] and "jti" in payload:
            self._validate_jti(payload)

    def _validate_required_claims(
        self,
        payload: dict[str, Any],
        claims: Iterable[str],
    ) -> None:
        for claim in claims:
            if claim not in payload or payload[claim] is None:
                raise MissingRequiredClaimError(claim)

    def _validate_sub(self, payload: dict[str, Any], subject: str | None = None) -> None:
        if "sub" not in payload:
            return

        if not isinstance(payload["sub"], str):
            raise InvalidSubjectError("Subject must be a string")

        if subject is not None and payload.get("sub") != subject:
            raise InvalidSubjectError("Invalid subject")

    def _validate_jti(self, payload: dict[str, Any]) -> None:
        if "jti" not in payload:
            return

        if not isinstance(payload.get("jti"), str):
            raise InvalidJTIError("JWT ID must be a string")

    def _validate_iat(self, payload: dict[str, Any], now: float, leeway: float) -> None:
        try:
            iat = int(payload["iat"])
        except ValueError:
            raise InvalidIssuedAtError("Issued At claim (iat) must be an integer.") from None
        if iat > (now + leeway):
            raise ImmatureSignatureError("The token is not yet valid (iat)")

    def _validate_nbf(self, payload: dict[str, Any], now: float, leeway: float) -> None:
        try:
            nbf = int(payload["nbf"])
        except ValueError:
            raise DecodeError("Not Before claim (nbf) must be an integer.") from None
        if nbf > (now + leeway):
            raise ImmatureSignatureError("The token is not yet valid (nbf)")

    def _validate_exp(self, payload: dict[str, Any], now: float, leeway: float) -> None:
        try:
            exp = int(payload["exp"])
        except ValueError:
            raise DecodeError("Expiration Time claim (exp) must be an integer.") from None
        if exp <= (now - leeway):
            raise ExpiredSignatureError("Signature has expired")

    def _validate_aud(
        self,
        payload: dict[str, Any],
        audience: str | Iterable[str] | None,
        *,
        strict: bool = False,
    ) -> None:
        if audience is None:
            if "aud" not in payload or not payload["aud"]:
                return
            raise InvalidAudienceError("Invalid audience")

        if "aud" not in payload or not payload["aud"]:
            raise MissingRequiredClaimError("aud")

        audience_claims = payload["aud"]

        if strict:
            if not isinstance(audience, str):
                raise InvalidAudienceError("Invalid audience (strict)")
            if not isinstance(audience_claims, str):
                raise InvalidAudienceError("Invalid claim format in token (strict)")
            if audience != audience_claims:
                raise InvalidAudienceError("Audience doesn't match (strict)")
            return

        if isinstance(audience_claims, str):
            audience_claims = [audience_claims]
        if not isinstance(audience_claims, list):
            raise InvalidAudienceError("Invalid claim format in token")
        if any(not isinstance(c, str) for c in audience_claims):
            raise InvalidAudienceError("Invalid claim format in token")

        if isinstance(audience, str):
            audience = [audience]

        if all(aud not in audience_claims for aud in audience):
            raise InvalidAudienceError("Audience doesn't match")

    def _validate_iss(
        self, payload: dict[str, Any], issuer: Container[str] | str | None
    ) -> None:
        if issuer is None:
            return

        if "iss" not in payload:
            raise MissingRequiredClaimError("iss")

        iss = payload["iss"]
        if not isinstance(iss, str):
            raise InvalidIssuerError("Payload Issuer (iss) must be a string")

        if isinstance(issuer, str):
            if iss != issuer:
                raise InvalidIssuerError("Invalid issuer")
        else:
            try:
                if iss not in issuer:
                    raise InvalidIssuerError("Invalid issuer")
            except TypeError:
                raise InvalidIssuerError('Issuer param must be "str" or "Container[str]"') from None


_jwt_global_obj = PyJWT()
_jwt_global_obj._jws = _jws_global_obj
encode = _jwt_global_obj.encode
decode_complete = _jwt_global_obj.decode_complete
decode = _jwt_global_obj.decode
