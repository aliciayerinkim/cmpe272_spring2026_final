#!/usr/bin/env python3
"""End-to-end smoke test: Approach A (mTLS) + Approach B (envelope) with a small file.

Creates a 1 MiB payload in a temp directory (never loads it whole), ensures dev
certs/keys exist, runs receiver → sender subprocess pairs with wall-clock
timeouts, and compares streaming SHA-256 hashes. Verification settings on the TLS
and envelope binaries are unchanged (no skips).

Examples:

  python scripts/smoke_test_all.py
  python scripts/smoke_test_all.py --size 65536 --phase-timeout 60
"""

from __future__ import annotations

import argparse
import platform
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

UTC = timezone.utc

REPO_ROOT = Path(__file__).resolve().parents[1]

REQUIRED_MTLS_PEMS = (
    "ca-cert.pem",
    "ca-key.pem",
    "server-cert.pem",
    "server-key.pem",
    "client-cert.pem",
    "client-key.pem",
)

REQUIRED_ENVELOPE_PEMS = (
    "sender_ed25519_private.pem",
    "sender_ed25519_public.pem",
    "sender_x25519_private.pem",
    "sender_x25519_public.pem",
    "receiver_ed25519_private.pem",
    "receiver_ed25519_public.pem",
    "receiver_x25519_private.pem",
    "receiver_x25519_public.pem",
)


def _bootstrap() -> None:
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))


def _streaming_sha256_hex(path: Path) -> str:
    _bootstrap()
    from common.hashing import sha256_hex_digest_file

    return sha256_hex_digest_file(path).lower()


def _mtls_cert_dir() -> Path:
    return REPO_ROOT / "approach-a-mtls" / "certs"


def _envelope_keys_dir() -> Path:
    return REPO_ROOT / "approach-b-envelope" / "keys"


def _mtls_material_complete() -> bool:
    d = _mtls_cert_dir()
    return all((d / name).is_file() for name in REQUIRED_MTLS_PEMS)


def _envelope_keys_complete() -> bool:
    d = _envelope_keys_dir()
    return all((d / name).is_file() for name in REQUIRED_ENVELOPE_PEMS)


def _run_generator(cmd: list[str], *, timeout: float) -> None:
    """Run ``generate_certs.py`` / ``generate_keys.py`` subprocess."""
    proc = subprocess.run(
        cmd,
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
    )
    if proc.returncode != 0:
        out = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()
        raise RuntimeError(f"{cmd[-2]} exited {proc.returncode}\n{out}")


def _ensure_mtls_certs(timeout: float) -> None:
    if _mtls_material_complete():
        return
    py = sys.executable
    gen = REPO_ROOT / "approach-a-mtls" / "generate_certs.py"
    _run_generator([py, str(gen), "--force"], timeout=timeout)


def _ensure_envelope_keys(timeout: float) -> None:
    if _envelope_keys_complete():
        return
    py = sys.executable
    gen = REPO_ROOT / "approach-b-envelope" / "generate_keys.py"
    _run_generator([py, str(gen), "--force"], timeout=timeout)


def _write_small_payload(dest: Path, size: int, timeout: float) -> None:
    py = sys.executable
    script = REPO_ROOT / "scripts" / "make_test_file.py"
    proc = subprocess.run(
        [py, str(script), "--size", str(size), "--output", str(dest)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
    )
    if proc.returncode != 0:
        out = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()
        raise RuntimeError(f"make_test_file failed: {out}")
    if not dest.is_file():
        raise RuntimeError(f"missing payload {dest}")
    if dest.stat().st_size != size:
        raise RuntimeError(f"payload size mismatch: wanted {size} got {dest.stat().st_size}")


def _run_transfer_phase(
    *,
    recv_cmd: list[str],
    send_cmd: list[str],
    startup_delay: float,
    phase_timeout: float,
) -> tuple[bool, str]:
    proc_recv = subprocess.Popen(
        recv_cmd,
        cwd=REPO_ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    log_lines: list[str] = []

    try:
        time.sleep(startup_delay)
        if proc_recv.poll() is not None:
            tail = proc_recv.stdout.read() if proc_recv.stdout else ""
            log_lines.append(f"receiver_early_exit_code={proc_recv.returncode}")
            log_lines.append(tail[:4000])
            return False, "\n".join(log_lines)

        send_kw = {
            "cwd": REPO_ROOT,
            "capture_output": True,
            "text": True,
            "encoding": "utf-8",
            "errors": "replace",
        }
        if phase_timeout > 0:
            send_kw["timeout"] = phase_timeout
        proc_send = subprocess.run(send_cmd, **send_kw)

        sout = ((proc_send.stdout or "") + (proc_send.stderr or "")).strip()
        log_lines.append(f"sender_exit={proc_send.returncode}")
        log_lines.append(sout[:6000])

        try:
            rtail, _ = proc_recv.communicate(timeout=phase_timeout if phase_timeout > 0 else None)
        except subprocess.TimeoutExpired:
            proc_recv.kill()
            try:
                rtail = proc_recv.communicate(timeout=5.0)[0]
            except Exception:
                rtail = ""
            log_lines.append("receiver_TimeoutExpired")
            log_lines.append((rtail or "")[:4000])
            return False, "\n".join(log_lines)

        log_lines.append(f"receiver_exit={proc_recv.returncode}")
        log_lines.append((rtail or "").strip()[:6000])

        ok = proc_send.returncode == 0 and proc_recv.returncode == 0
        return ok, "\n".join(log_lines)
    except subprocess.TimeoutExpired as exc:
        log_lines.append(f"sender_or_phase_timeout:{exc}")
        return False, "\n".join(log_lines)
    finally:
        if proc_recv.poll() is None:
            proc_recv.kill()
            try:
                proc_recv.wait(timeout=5.0)
            except subprocess.TimeoutExpired:
                pass


def _approach_smoke_a(
    *,
    payload: Path,
    recv_out: Path,
    port: int,
    startup_delay: float,
    phase_timeout: float,
) -> tuple[bool, str]:
    remote = payload.name
    recv_out.mkdir(parents=True, exist_ok=True)
    py = sys.executable

    recv_cmd = [
        py,
        str(REPO_ROOT / "approach-a-mtls" / "receiver.py"),
        "--host",
        "127.0.0.1",
        "--port",
        str(port),
        "--output-dir",
        str(recv_out),
    ]
    send_cmd = [
        py,
        str(REPO_ROOT / "approach-a-mtls" / "sender.py"),
        "--host",
        "127.0.0.1",
        "--port",
        str(port),
        "--file",
        str(payload),
        "--remote-name",
        remote,
    ]
    ok, slog = _run_transfer_phase(
        recv_cmd=recv_cmd,
        send_cmd=send_cmd,
        startup_delay=startup_delay,
        phase_timeout=phase_timeout,
    )
    if not ok:
        return False, slog

    got = recv_out / remote
    if not got.is_file():
        return False, slog + "\nMISSING_OUTPUT_FILE"

    return True, slog


def _approach_smoke_b(
    *,
    payload: Path,
    recv_out: Path,
    port: int,
    startup_delay: float,
    phase_timeout: float,
) -> tuple[bool, str]:
    remote = payload.name
    recv_out.mkdir(parents=True, exist_ok=True)
    py = sys.executable

    recv_cmd = [
        py,
        str(REPO_ROOT / "approach-b-envelope" / "receiver.py"),
        "--host",
        "127.0.0.1",
        "--port",
        str(port),
        "--keys-dir",
        str(_envelope_keys_dir()),
        "--output-dir",
        str(recv_out),
    ]
    send_cmd = [
        py,
        str(REPO_ROOT / "approach-b-envelope" / "sender.py"),
        "--host",
        "127.0.0.1",
        "--port",
        str(port),
        "--keys-dir",
        str(_envelope_keys_dir()),
        "--file",
        str(payload),
        "--remote-name",
        remote,
    ]
    ok, slog = _run_transfer_phase(
        recv_cmd=recv_cmd,
        send_cmd=send_cmd,
        startup_delay=startup_delay,
        phase_timeout=phase_timeout,
    )
    if not ok:
        return False, slog

    got = recv_out / remote
    if not got.is_file():
        return False, slog + "\nMISSING_OUTPUT_FILE"

    return True, slog


def main(argv: list[str] | None = None) -> int:
    default_size = 1024 * 1024
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--size", type=int, default=default_size, help=f"Payload size in bytes (default {default_size}).")
    parser.add_argument("--port-a", type=int, default=48_543, help="Listening port for Approach A smoke.")
    parser.add_argument("--port-b", type=int, default=49_543, help="Listening port for Approach B smoke.")
    parser.add_argument(
        "--startup-delay",
        type=float,
        default=1.0,
        help="Seconds to wait after spawning receiver.",
    )
    parser.add_argument(
        "--phase-timeout",
        type=float,
        default=300.0,
        help=(
            "Per-phase wall-clock timeout (seconds) for sender subprocess and draining "
            "receiver stdout. ``0`` disables these timeouts (risk: may hang)."
        ),
    )
    parser.add_argument(
        "--generator-timeout",
        type=float,
        default=180.0,
        help="Timeout for cert/key/payload subprocess helpers.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print subprocess excerpts on PASS as well.",
    )
    args = parser.parse_args(argv)

    pyver = sys.version.split()[0]
    plat = platform.platform()
    stamp = datetime.now(UTC).isoformat()
    print(f"=== CMPE272 smoke_test_all ({stamp}) Python={pyver} platform={plat}", flush=True)

    if args.size <= 0:
        print("FAIL: --size must be positive", flush=True)
        return 1

    tmp_parent = tempfile.gettempdir()
    tmp = Path(tempfile.mkdtemp(prefix="cmpe272_smoke_", dir=tmp_parent))
    payload = tmp / "smoke_payload.bin"
    recv_a = tmp / "recv_mtls"
    recv_b = tmp / "recv_envelope"

    try:
        print(f"Scratch dir: {tmp}", flush=True)
        _write_small_payload(payload, int(args.size), timeout=float(args.generator_timeout))
        hin = _streaming_sha256_hex(payload)
        print(f"PAYLOAD_BYTES={payload.stat().st_size} INPUT_SHA256={hin}", flush=True)

        print("Ensuring mTLS certs (no verification weakening)...", flush=True)
        try:
            _ensure_mtls_certs(timeout=float(args.generator_timeout))
        except Exception as exc:
            print(f"APPROACH_A: FAIL ({exc})", flush=True)
            return 1

        print("Ensuring envelope keys...", flush=True)
        try:
            _ensure_envelope_keys(timeout=float(args.generator_timeout))
        except Exception as exc:
            print(f"APPROACH_B: FAIL setup:{exc}", flush=True)
            return 1

        print("Running Approach A (mTLS)...", flush=True)
        ok_a, log_a = _approach_smoke_a(
            payload=payload,
            recv_out=recv_a,
            port=int(args.port_a),
            startup_delay=float(args.startup_delay),
            phase_timeout=float(args.phase_timeout),
        )
        if ok_a:
            ho = _streaming_sha256_hex(recv_a / payload.name)
            ok_a = ho == hin
            if ok_a:
                print(f"APPROACH_A: PASS SHA256_matches output={ho}", flush=True)
            else:
                print(f"APPROACH_A: FAIL SHA256_mismatch expected={hin} got={ho}", flush=True)
        else:
            print(f"APPROACH_A: FAIL subprocess\n{log_a}", flush=True)
        if args.verbose and ok_a:
            print("--- Approach A subprocess log excerpt ---", flush=True)
            print(log_a[:4000], flush=True)

        print("Running Approach B (envelope)...", flush=True)
        ok_b, log_b = _approach_smoke_b(
            payload=payload,
            recv_out=recv_b,
            port=int(args.port_b),
            startup_delay=float(args.startup_delay),
            phase_timeout=float(args.phase_timeout),
        )
        if ok_b:
            ho2 = _streaming_sha256_hex(recv_b / payload.name)
            ok_b = ho2 == hin
            if ok_b:
                print(f"APPROACH_B: PASS SHA256_matches output={ho2}", flush=True)
            else:
                print(f"APPROACH_B: FAIL SHA256_mismatch expected={hin} got={ho2}", flush=True)
        else:
            print(f"APPROACH_B: FAIL subprocess\n{log_b}", flush=True)
        if args.verbose and ok_b:
            print("--- Approach B subprocess log excerpt ---", flush=True)
            print(log_b[:4000], flush=True)

        overall = ok_a and ok_b
        print(f"OVERALL: {'PASS' if overall else 'FAIL'}", flush=True)
        return 0 if overall else 1
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
