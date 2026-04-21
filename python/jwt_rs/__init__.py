from . import algorithms, types
from .api_jwk import PyJWK, PyJWKSet
from .api_jws import (
    PyJWS,
    get_algorithm_by_name,
    get_unverified_header,
    register_algorithm,
    unregister_algorithm,
)
from .api_jwt import PyJWT, decode, decode_complete, encode
from .exceptions import (
    DecodeError,
    ExpiredSignatureError,
    ImmatureSignatureError,
    InvalidAlgorithmError,
    InvalidAudienceError,
    InvalidIssuedAtError,
    InvalidIssuerError,
    InvalidJTIError,
    InvalidKeyError,
    InvalidSignatureError,
    InvalidSubjectError,
    InvalidTokenError,
    MissingRequiredClaimError,
    PyJWKClientConnectionError,
    PyJWKClientError,
    PyJWKError,
    PyJWKSetError,
    PyJWTError,
)
from .jwks_client import PyJWKClient
from .warnings import InsecureKeyLengthWarning

__version__ = "2.12.1"
# Distribution version of the pyjwt-rs package itself (separate from the PyJWT
# compatibility version above). See VERSIONING.md for the two-axis policy.
__pyjwt_rs_version__ = "1.1.0"

__title__ = "PyJWT"
__description__ = "JSON Web Token implementation in Python"
__url__ = "https://pyjwt.readthedocs.io"
__uri__ = __url__
__doc__ = f"{__description__} <{__uri__}>"

__author__ = "José Padilla"
__email__ = "hello@jpadilla.com"

__license__ = "MIT"
__copyright__ = "Copyright 2015-2026 José Padilla"

__all__ = [
    "__pyjwt_rs_version__",
    "algorithms",
    "types",
    "PyJWS",
    "PyJWT",
    "PyJWK",
    "PyJWKSet",
    "PyJWKClient",
    "decode",
    "decode_complete",
    "encode",
    "get_unverified_header",
    "register_algorithm",
    "unregister_algorithm",
    "get_algorithm_by_name",
    "InsecureKeyLengthWarning",
    "DecodeError",
    "ExpiredSignatureError",
    "ImmatureSignatureError",
    "InvalidAlgorithmError",
    "InvalidAudienceError",
    "InvalidIssuedAtError",
    "InvalidIssuerError",
    "InvalidJTIError",
    "InvalidKeyError",
    "InvalidSignatureError",
    "InvalidSubjectError",
    "InvalidTokenError",
    "MissingRequiredClaimError",
    "PyJWKClientConnectionError",
    "PyJWKClientError",
    "PyJWKError",
    "PyJWKSetError",
    "PyJWTError",
]
