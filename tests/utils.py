import os
from base64 import urlsafe_b64encode
from calendar import timegm
from datetime import datetime, timezone

import pytest

from jwt_rs.algorithms import has_crypto


HS256_SECRET = "0123456789abcdef0123456789abcdef"
HS384_SECRET = "0123456789abcdef0123456789abcdef0123456789abcdef"
HS512_SECRET = (
    "0123456789abcdef0123456789abcdef"
    "0123456789abcdef0123456789abcdef"
)

HS256_SECRET_B64U = urlsafe_b64encode(HS256_SECRET.encode()).decode().rstrip("=")
HS384_SECRET_B64U = urlsafe_b64encode(HS384_SECRET.encode()).decode().rstrip("=")
HS512_SECRET_B64U = urlsafe_b64encode(HS512_SECRET.encode()).decode().rstrip("=")


def utc_timestamp() -> int:
    return timegm(datetime.now(tz=timezone.utc).utctimetuple())


def key_path(key_name: str) -> str:
    return os.path.join(os.path.dirname(os.path.realpath(__file__)), "keys", key_name)


no_crypto_required = pytest.mark.skipif(
    has_crypto,
    reason="Requires cryptography library not installed",
)


crypto_required = pytest.mark.skipif(
    not has_crypto,
    reason="Requires cryptography library installed",
)
