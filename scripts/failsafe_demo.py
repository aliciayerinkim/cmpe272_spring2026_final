#!/usr/bin/env python3
"""Demonstrate fail-safe receivers: abort an in-flight sender, prove no final file, then finish.

Uses a modest payload under system ``temp`` (default 8 MiB, must be larger than ``1 MiB`` so
partial ``Sending:`` progress lines occur) then kills the sender **after** the first stdout line
shows ``Sending: uploaded/total`` with uploaded < total, plus an extra ``--kill-after`` grace delay.

Runs Approach A (mTLS) and/or Approach B (envelope) without changing wire crypto.

Examples:

  python scripts/failsafe_demo.py

  python scripts/failsafe_demo.py --kill-after 0.5 --size 16777216

  python scripts/failsafe_demo.py --approach b
"""

from __future__ import annotations

import argparse
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

UTC = timezone.utc

DEFAULT_PORT_A = 58_443
DEFAULT_PORT_B = 59_443

_SENDING_PROGRESS_RE = re.compile(r"Sending:\s+(\d+)/(\d+)\s+bytes")

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
        raise RuntimeError(f"generator exited {proc.returncode}\n{out}")


def ensure_mtls_certs(timeout: float) -> None:
    if _mtls_material_complete():
        return
    py = sys.executable
    gen = REPO_ROOT / "approach-a-mtls" / "generate_certs.py"
    _run_generator([py, str(gen), "--force"], timeout=timeout)


def ensure_envelope_keys(timeout: float) -> None:
    if _envelope_keys_complete():
        return
    py = sys.executable
    gen = REPO_ROOT / "approach-b-envelope" / "generate_keys.py"
    _run_generator([py, str(gen), "--force"], timeout=timeout)


def write_payload(py: Path, dest: Path, size: int, timeout: float) -> None:
    script = REPO_ROOT / "scripts" / "make_test_file.py"
    proc = subprocess.run(
        [str(py), str(script), "--size", str(size), "--output", str(dest)],
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
    if not dest.is_file() or dest.stat().st_size != size:
        raise RuntimeError(f"payload mismatch: wanted {size} bytes")


def describe_leftovers(recv_root: Path) -> str:
    parts = sorted(recv_root.glob("*.part"))
    q = recv_root / ".quarantine"
    q_entries = sorted(q.glob("*")) if q.is_dir() else []
    chunks = []
    if parts:
        chunks.append(".part -> " + ", ".join(p.name for p in parts))
    else:
        chunks.append(".part -> none")
    if q_entries:
        chunks.append(".quarantine -> " + ", ".join(e.name for e in q_entries))
    else:
        chunks.append(".quarantine -> empty or missing")
    return "; ".join(chunks)


def _wait_for_partial_sending_line(
    pipe,
    *,
    deadline: float,
    file_size: int,
    min_remainder_bytes: int,
) -> tuple[int, int]:
    """Return (uploaded, total) once senders emit ``Sending`` with sizeable bytes left to ship."""
    while time.monotonic() < deadline:
        line = pipe.readline()
        if not line:
            raise RuntimeError("sender stdout closed before partial Sending progress")
        m = _SENDING_PROGRESS_RE.search(line)
        if not m:
            continue
        up, total = int(m.group(1)), int(m.group(2))
        if total != file_size:
            continue
        if up < total and (total - up) >= min_remainder_bytes:
            return up, total
    raise TimeoutError("timed out waiting for early partial Sending progress from sender")


def _wait_proc(proc: subprocess.Popen, *, label: str, timeout: float) -> None:
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=10.0)
        raise TimeoutError(f"{label} still running after {timeout}s")


def phase_abort_then_assert_no_final(
    *,
    py: Path,
    label: str,
    recv_script: Path,
    send_script: Path,
    recv_root: Path,
    payload: Path,
    port: int,
    startup_delay: float,
    kill_after: float,
    recv_extra: list[str],
    send_extra: list[str],
    file_size_bytes: int,
    min_remainder_bytes: int,
) -> None:
    remote = payload.name
    final_path = recv_root / remote
    recv_root.mkdir(parents=True, exist_ok=True)
    if final_path.exists():
        final_path.unlink()

    recv_cmd = [
        str(py),
        str(recv_script),
        "--host",
        "127.0.0.1",
        "--port",
        str(port),
        "--output-dir",
        str(recv_root),
        *recv_extra,
    ]
    recv_proc = subprocess.Popen(
        recv_cmd,
        cwd=REPO_ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    send_cmd = [
        str(py),
        str(send_script),
        "--host",
        "127.0.0.1",
        "--port",
        str(port),
        *send_extra,
        "--file",
        str(payload),
        "--remote-name",
        remote,
    ]
    send_proc: subprocess.Popen | None = None

    print(
        f"[{label}] Abort phase starting (terminate sender mid-payload via partial "
        f"Sending: line + {kill_after}s grace)...",
        flush=True,
    )
    try:
        time.sleep(startup_delay)
        if recv_proc.poll() is not None:
            raise RuntimeError("receiver exited before sender started")

        send_proc = subprocess.Popen(
            send_cmd,
            cwd=REPO_ROOT,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        assert send_proc.stdout is not None
        _wait_for_partial_sending_line(
            send_proc.stdout,
            deadline=time.monotonic() + 120.0,
            file_size=file_size_bytes,
            min_remainder_bytes=min_remainder_bytes,
        )
        if kill_after > 0:
            time.sleep(kill_after)
        send_proc.kill()
        try:
            send_proc.wait(timeout=30.0)
        except subprocess.TimeoutExpired:
            send_proc.kill()
            send_proc.wait(timeout=30.0)
        finally:
            try:
                send_proc.communicate(timeout=15.0)
            except Exception:
                pass
    finally:
        _wait_proc(recv_proc, label=f"{label} receiver (abort cleanup)", timeout=120.0)
        if send_proc is not None and send_proc.poll() is None:
            try:
                send_proc.kill()
                send_proc.wait(timeout=10.0)
            except Exception:
                pass
    if final_path.exists():
        raise RuntimeError(f"{label}: expected no final output {final_path}")

    leftovers = describe_leftovers(recv_root)
    print(f"[{label}] OK: final file absent ({final_path}). Leftovers summary: {leftovers}", flush=True)


def phase_complete_verify(
    *,
    py: Path,
    label: str,
    recv_script: Path,
    send_script: Path,
    recv_root: Path,
    payload: Path,
    expected_sha256: str,
    port: int,
    startup_delay: float,
    phase_timeout: float,
    recv_extra: list[str],
    send_extra: list[str],
) -> None:
    remote = payload.name
    recv_root.mkdir(parents=True, exist_ok=True)

    recv_cmd = [
        str(py),
        str(recv_script),
        "--host",
        "127.0.0.1",
        "--port",
        str(port),
        "--output-dir",
        str(recv_root),
        *recv_extra,
    ]
    recv_proc = subprocess.Popen(
        recv_cmd,
        cwd=REPO_ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
    )

    send_cmd = [
        str(py),
        str(send_script),
        "--host",
        "127.0.0.1",
        "--port",
        str(port),
        *send_extra,
        "--file",
        str(payload),
        "--remote-name",
        remote,
    ]

    print(f"[{label}] Restarting full transfer (same output dir)...", flush=True)

    send_rc = None
    try:
        time.sleep(startup_delay)
        if recv_proc.poll() is not None:
            out = recv_proc.communicate(timeout=5.0)[0] if recv_proc.stdout else ""
            raise RuntimeError(f"receiver exited early:{out}")

        snd = subprocess.run(
            send_cmd,
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=phase_timeout,
        )
        send_rc = snd.returncode

        recv_out, _ = recv_proc.communicate(timeout=max(phase_timeout, 180.0))
        if recv_proc.returncode != 0:
            print((recv_out or "").strip()[:4000], file=sys.stderr, flush=True)
            raise RuntimeError(f"receiver exited {recv_proc.returncode}")
        if send_rc != 0:
            sout = ((snd.stdout or "") + "\n" + (snd.stderr or "")).strip()
            raise RuntimeError(f"sender exited {send_rc}\n{sout[:4000]}")

        got_path = recv_root / remote
        if not got_path.is_file():
            raise RuntimeError(f"missing committed file after success: {got_path}")

        digest = _streaming_sha256_hex(got_path)
        if digest != expected_sha256:
            raise RuntimeError(f"{label}: SHA-256 mismatch input={expected_sha256} received={digest}")
        print(f"[{label}] OK: SHA-256 matches digest={digest}", flush=True)
    except subprocess.TimeoutExpired as exc:
        recv_proc.kill()
        try:
            recv_proc.communicate(timeout=15.0)
        except Exception:
            pass
        raise RuntimeError(f"{label}: timeout ({exc})") from exc


def main(argv: list[str] | None = None) -> int:
    default_size = 8 * 1024 * 1024
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--size",
        type=int,
        default=default_size,
        help=f"Payload size in bytes (default {default_size}, i.e. 8 MiB).",
    )
    parser.add_argument(
        "--kill-after",
        type=float,
        default=0.0,
        help="Optional seconds to sleep **after** an early Sending: line **before killing** the sender (danger: transfer may finish).",
    )
    parser.add_argument(
        "--min-remainder-bytes",
        type=int,
        default=786_432,
        help=(
            "Abort-kill fires only once stdout shows Sending with at least this many bytes left "
            "(default ~768 KiB, reduces race where loopback completes the tail before SIGKILL)."
        ),
    )
    parser.add_argument(
        "--startup-delay",
        type=float,
        default=0.8,
        help="Seconds to sleep after spawning receiver before spawning sender.",
    )
    parser.add_argument("--port-a", type=int, default=DEFAULT_PORT_A, help="Approach A listen port.")
    parser.add_argument("--port-b", type=int, default=DEFAULT_PORT_B, help="Approach B listen port.")
    parser.add_argument(
        "--approach",
        choices=("a", "b", "both"),
        default="both",
        help="Which stack(s) to exercise.",
    )
    parser.add_argument(
        "--phase-timeout",
        type=float,
        default=900.0,
        help="Timeout (seconds) for the successful sender run (+ receiver drain).",
    )
    parser.add_argument("--generator-timeout", type=float, default=180.0, help="Subprocess timeouts for gens.")
    parser.add_argument(
        "--keep-temp-dir",
        action="store_true",
        help="Do not delete the scratch directory (shows paths printed at start).",
    )
    args = parser.parse_args(argv)

    if int(args.size) <= 0:
        print("ERROR: --size must be positive", file=sys.stderr)
        return 1
    if int(args.size) <= 1024 * 1024:
        print(
            "ERROR: --size must exceed 1 MiB so senders emit a partial Sending progress line.",
            file=sys.stderr,
        )
        return 1
    stamp = datetime.now(UTC).isoformat()
    print(f"=== failsafe_demo.py ({stamp}) platform={platform.platform()}", flush=True)

    py = Path(sys.executable)
    tmp_parent = tempfile.gettempdir()
    tmp = Path(tempfile.mkdtemp(prefix="cmpe272_failsafe_", dir=tmp_parent))
    payload = tmp / "failsafe_payload.bin"
    recv_a = tmp / "received_a_failsafe"
    recv_b = tmp / "received_b_failsafe"

    try:
        write_payload(py, payload, int(args.size), timeout=float(args.generator_timeout))
        inp_sha = _streaming_sha256_hex(payload)
        print(f"Scratch dir: {tmp}", flush=True)
        print(f"PAYLOAD_BYTES={payload.stat().st_size} INPUT_SHA256={inp_sha}", flush=True)

        if args.approach in ("a", "both"):
            print("Ensuring mTLS certs...", flush=True)
            ensure_mtls_certs(timeout=float(args.generator_timeout))

            phase_abort_then_assert_no_final(
                py=py,
                label="Approach-A",
                recv_script=REPO_ROOT / "approach-a-mtls" / "receiver.py",
                send_script=REPO_ROOT / "approach-a-mtls" / "sender.py",
                recv_root=recv_a,
                payload=payload,
                port=int(args.port_a),
                startup_delay=float(args.startup_delay),
                kill_after=float(args.kill_after),
                recv_extra=[],
                send_extra=["--chunk-size", "65536", "--progress-interval-mib", "1"],
                file_size_bytes=int(payload.stat().st_size),
                min_remainder_bytes=int(args.min_remainder_bytes),
            )
            phase_complete_verify(
                py=py,
                label="Approach-A",
                recv_script=REPO_ROOT / "approach-a-mtls" / "receiver.py",
                send_script=REPO_ROOT / "approach-a-mtls" / "sender.py",
                recv_root=recv_a,
                payload=payload,
                expected_sha256=inp_sha,
                port=int(args.port_a),
                startup_delay=float(args.startup_delay),
                phase_timeout=float(args.phase_timeout),
                recv_extra=[],
                send_extra=[],
            )

        if args.approach in ("b", "both"):
            print("Ensuring envelope keys...", flush=True)
            ensure_envelope_keys(timeout=float(args.generator_timeout))

            keys = str(_envelope_keys_dir())
            phase_abort_then_assert_no_final(
                py=py,
                label="Approach-B",
                recv_script=REPO_ROOT / "approach-b-envelope" / "receiver.py",
                send_script=REPO_ROOT / "approach-b-envelope" / "sender.py",
                recv_root=recv_b,
                payload=payload,
                port=int(args.port_b),
                startup_delay=float(args.startup_delay),
                kill_after=float(args.kill_after),
                recv_extra=["--keys-dir", keys],
                send_extra=[
                    "--keys-dir",
                    keys,
                    "--chunk-plaintext-max",
                    "65536",
                    "--progress-interval-mib",
                    "1",
                ],
                file_size_bytes=int(payload.stat().st_size),
                min_remainder_bytes=int(args.min_remainder_bytes),
            )
            phase_complete_verify(
                py=py,
                label="Approach-B",
                recv_script=REPO_ROOT / "approach-b-envelope" / "receiver.py",
                send_script=REPO_ROOT / "approach-b-envelope" / "sender.py",
                recv_root=recv_b,
                payload=payload,
                expected_sha256=inp_sha,
                port=int(args.port_b),
                startup_delay=float(args.startup_delay),
                phase_timeout=float(args.phase_timeout),
                recv_extra=["--keys-dir", keys],
                send_extra=["--keys-dir", keys],
            )

        print("OVERALL: PASS (abort left no trusted final file; restarted transfer hashed clean)", flush=True)
        return 0
    except Exception as exc:
        print(f"OVERALL: FAIL ({exc})", file=sys.stderr, flush=True)
        return 1
    finally:
        if not args.keep_temp_dir:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
