from __future__ import annotations

import argparse
import statistics
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

import jwt_rs
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa


def utc_now() -> datetime:
    return datetime.now(tz=timezone.utc)


def payload() -> dict[str, Any]:
    return {
        "sub": "alice",
        "scope": ["read", "write"],
        "iat": utc_now(),
        "nbf": utc_now(),
        "exp": utc_now() + timedelta(minutes=10),
        "meta": {"tenant": "acme", "roles": ["admin", "billing"]},
    }


@dataclass(frozen=True)
class ComponentCase:
    name: str
    setup: Callable[[], dict[str, Callable[[], Any]]]


def build_hs256_case() -> dict[str, Callable[[], Any]]:
    jws = jwt_rs.api_jws.PyJWS()
    secret = "benchmark-secret-key-material-32bytes"
    token = jwt_rs.encode(payload(), secret, algorithm="HS256")
    loaded = jws._load(token)
    prepared = jwt_rs.algorithms.prepare_rust_handle(secret, "HS256", "decode")
    alg = jws.get_algorithm_by_name("HS256")
    return {
        "load": lambda: jws._load(token),
        "verify_only": lambda: alg.verify(loaded[1], prepared or alg.prepare_key(secret), loaded[3]),
        "decode": lambda: jwt_rs.decode(token, secret, algorithms=["HS256"]),
        "decode_complete": lambda: jwt_rs.decode_complete(token, secret, algorithms=["HS256"]),
    }


def build_rs256_case() -> dict[str, Callable[[], Any]]:
    jws = jwt_rs.api_jws.PyJWS()
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    token = jwt_rs.encode(payload(), private_pem, algorithm="RS256")
    loaded = jws._load(token)
    prepared = jwt_rs.algorithms.prepare_rust_handle(public_pem, "RS256", "decode")
    alg = jws.get_algorithm_by_name("RS256")
    return {
        "load": lambda: jws._load(token),
        "verify_only": lambda: alg.verify(loaded[1], prepared or alg.prepare_key(public_pem), loaded[3]),
        "decode": lambda: jwt_rs.decode(token, public_pem, algorithms=["RS256"]),
        "decode_complete": lambda: jwt_rs.decode_complete(token, public_pem, algorithms=["RS256"]),
    }


def build_es256_case() -> dict[str, Callable[[], Any]]:
    jws = jwt_rs.api_jws.PyJWS()
    private_key = ec.generate_private_key(ec.SECP256R1())
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    token = jwt_rs.encode(payload(), private_pem, algorithm="ES256")
    loaded = jws._load(token)
    prepared = jwt_rs.algorithms.prepare_rust_handle(public_pem, "ES256", "decode")
    alg = jws.get_algorithm_by_name("ES256")
    return {
        "load": lambda: jws._load(token),
        "verify_only": lambda: alg.verify(loaded[1], prepared or alg.prepare_key(public_pem), loaded[3]),
        "decode": lambda: jwt_rs.decode(token, public_pem, algorithms=["ES256"]),
        "decode_complete": lambda: jwt_rs.decode_complete(token, public_pem, algorithms=["ES256"]),
    }


def build_eddsa_case() -> dict[str, Callable[[], Any]]:
    jws = jwt_rs.api_jws.PyJWS()
    private_key = ed25519.Ed25519PrivateKey.generate()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    token = jwt_rs.encode(payload(), private_pem, algorithm="EdDSA")
    loaded = jws._load(token)
    prepared = jwt_rs.algorithms.prepare_rust_handle(public_pem, "EdDSA", "decode")
    alg = jws.get_algorithm_by_name("EdDSA")
    return {
        "load": lambda: jws._load(token),
        "verify_only": lambda: alg.verify(loaded[1], prepared or alg.prepare_key(public_pem), loaded[3]),
        "decode": lambda: jwt_rs.decode(token, public_pem, algorithms=["EdDSA"]),
        "decode_complete": lambda: jwt_rs.decode_complete(token, public_pem, algorithms=["EdDSA"]),
    }


CASES = [
    ComponentCase("hs256", build_hs256_case),
    ComponentCase("rs256", build_rs256_case),
    ComponentCase("es256", build_es256_case),
    ComponentCase("eddsa", build_eddsa_case),
]


def time_call(fn: Callable[[], Any], iterations: int, warmup: int) -> list[float]:
    for _ in range(warmup):
        fn()
    samples: list[float] = []
    for _ in range(iterations):
        start = time.perf_counter_ns()
        fn()
        end = time.perf_counter_ns()
        samples.append((end - start) / 1_000_000_000)
    return samples


def summarize(samples: list[float]) -> dict[str, float]:
    mean = statistics.fmean(samples)
    median = statistics.median(samples)
    return {
        "mean_s": mean,
        "median_s": median,
        "ops_per_s": 0.0 if mean == 0 else 1.0 / mean,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iterations", type=int, default=300)
    parser.add_argument("--warmup", type=int, default=40)
    args = parser.parse_args()

    for case in CASES:
        print(f"\n[{case.name}]")
        functions = case.setup()
        for label, fn in functions.items():
            stats = summarize(time_call(fn, args.iterations, args.warmup))
            print(
                f"{label:16} mean={stats['mean_s']:.6f}s "
                f"median={stats['median_s']:.6f}s ops/s={stats['ops_per_s']:.2f}"
            )


if __name__ == "__main__":
    main()
