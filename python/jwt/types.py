from typing import Any, Callable, TypedDict

JWKDict = dict[str, Any]

HashlibHash = Callable[..., Any]


class SigOptions(TypedDict, total=False):
    verify_signature: bool
    enforce_minimum_key_length: bool


class Options(TypedDict, total=False):
    verify_signature: bool
    require: list[str]
    strict_aud: bool
    verify_aud: bool
    verify_exp: bool
    verify_iat: bool
    verify_iss: bool
    verify_jti: bool
    verify_nbf: bool
    verify_sub: bool
    enforce_minimum_key_length: bool


class FullOptions(TypedDict):
    verify_signature: bool
    require: list[str]
    strict_aud: bool
    verify_aud: bool
    verify_exp: bool
    verify_iat: bool
    verify_iss: bool
    verify_jti: bool
    verify_nbf: bool
    verify_sub: bool
    enforce_minimum_key_length: bool
