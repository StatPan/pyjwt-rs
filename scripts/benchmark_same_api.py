from __future__ import annotations

import argparse
import json
import statistics
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

import jwt as pyjwt
import jwt_rs
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa


JwtModule = Any


@dataclass(frozen=True)
class BenchCase:
    name: str
    algorithm: str
    setup: Callable[[JwtModule], tuple[Callable[[], Any], Callable[[], Any], Callable[[], Any], Callable[[], Any]]]


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


def build_hs256_case(module: JwtModule) -> tuple[Callable[[], Any], Callable[[], Any], Callable[[], Any], Callable[[], Any]]:
    secret = "benchmark-secret-key-material-32bytes"
    token = module.encode(payload(), secret, algorithm="HS256")
    return (
        lambda: module.encode(payload(), secret, algorithm="HS256"),
        lambda: module.decode(token, secret, algorithms=["HS256"]),
        lambda: module.decode_complete(token, secret, algorithms=["HS256"]),
        lambda: module.get_unverified_header(token),
    )


def build_rs256_case(module: JwtModule) -> tuple[Callable[[], Any], Callable[[], Any], Callable[[], Any], Callable[[], Any]]:
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
    token = module.encode(payload(), private_pem, algorithm="RS256")
    return (
        lambda: module.encode(payload(), private_pem, algorithm="RS256"),
        lambda: module.decode(token, public_pem, algorithms=["RS256"]),
        lambda: module.decode_complete(token, public_pem, algorithms=["RS256"]),
        lambda: module.get_unverified_header(token),
    )


def build_es256_case(module: JwtModule) -> tuple[Callable[[], Any], Callable[[], Any], Callable[[], Any], Callable[[], Any]]:
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
    token = module.encode(payload(), private_pem, algorithm="ES256")
    return (
        lambda: module.encode(payload(), private_pem, algorithm="ES256"),
        lambda: module.decode(token, public_pem, algorithms=["ES256"]),
        lambda: module.decode_complete(token, public_pem, algorithms=["ES256"]),
        lambda: module.get_unverified_header(token),
    )


def build_eddsa_case(module: JwtModule) -> tuple[Callable[[], Any], Callable[[], Any], Callable[[], Any], Callable[[], Any]]:
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
    token = module.encode(payload(), private_pem, algorithm="EdDSA")
    return (
        lambda: module.encode(payload(), private_pem, algorithm="EdDSA"),
        lambda: module.decode(token, public_pem, algorithms=["EdDSA"]),
        lambda: module.decode_complete(token, public_pem, algorithms=["EdDSA"]),
        lambda: module.get_unverified_header(token),
    )


CASES = [
    BenchCase("hs256", "HS256", build_hs256_case),
    BenchCase("rs256", "RS256", build_rs256_case),
    BenchCase("es256", "ES256", build_es256_case),
    BenchCase("eddsa", "EdDSA", build_eddsa_case),
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
        "min_s": min(samples),
        "max_s": max(samples),
    }


def run_module_bench(
    module_name: str,
    module: JwtModule,
    iterations: int,
    warmup: int,
) -> dict[str, dict[str, float]]:
    results: dict[str, dict[str, float]] = {}
    for case in CASES:
        encode_fn, decode_fn, decode_complete_fn, header_fn = case.setup(module)
        results[f"{case.name}.encode"] = summarize(time_call(encode_fn, iterations, warmup))
        results[f"{case.name}.decode"] = summarize(time_call(decode_fn, iterations, warmup))
        results[f"{case.name}.decode_complete"] = summarize(
            time_call(decode_complete_fn, iterations, warmup)
        )
        results[f"{case.name}.get_unverified_header"] = summarize(
            time_call(header_fn, iterations, warmup)
        )
    print(f"\n[{module_name}]")
    for name, stats in results.items():
        print(
            f"{name:28} mean={stats['mean_s']:.6f}s "
            f"median={stats['median_s']:.6f}s ops/s={stats['ops_per_s']:.2f}"
        )
    return results


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iterations", type=int, default=200)
    parser.add_argument("--warmup", type=int, default=30)
    parser.add_argument("--json", action="store_true", dest="json_output")
    args = parser.parse_args()

    results = {
        "pyjwt": run_module_bench("pyjwt", pyjwt, args.iterations, args.warmup),
        "jwt_rs": run_module_bench("jwt_rs", jwt_rs, args.iterations, args.warmup),
    }

    speedups: dict[str, float] = {}
    for key, py_stats in results["pyjwt"].items():
        rs_stats = results["jwt_rs"][key]
        speedups[key] = (
            0.0 if rs_stats["mean_s"] == 0 else py_stats["mean_s"] / rs_stats["mean_s"]
        )

    print("\n[speedup pyjwt/jwt_rs]")
    for name, speedup in speedups.items():
        print(f"{name:28} {speedup:.2f}x")

    if args.json_output:
        print(json.dumps({"results": results, "speedups": speedups}, indent=2))


if __name__ == "__main__":
    main()
