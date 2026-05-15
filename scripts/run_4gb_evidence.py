#!/usr/bin/env python3
"""Verify a canonical 4 GiB file and record SHA-256 evidence for Approach A/B transfers.

Runs receiver + sender as subprocess (optional) using the same Python interpreter
(``sys.executable``) and repository root as cwd so ``common`` imports resolve.

Default input: ``zero4g.bin`` at repo root (exactly 4294967296 bytes). Prefer an
existing sparse, zero-filled ``zero4g.bin`` at that logical size for evidence;
see the ``--- 4 GiB evidence semantics ---`` block in each written log.

Examples:

  # Size + input hash + template only (no transfers)
  python scripts/run_4gb_evidence.py --no-transfers

  # Full automated run (requires certs/keys already generated)
  python scripts/run_4gb_evidence.py --input zero4g.bin --timeout-sec 0
"""

from __future__ import annotations

import argparse
import platform
import subprocess
import sys
import textwrap
import time
from datetime import datetime, timezone
from pathlib import Path

UTC = timezone.utc


REPO_ROOT = Path(__file__).resolve().parents[1]
_EXPECTED_BYTES = 4294967296  # 4 * 1024**3


def _four_gib_semantic_log_lines(*, input_path: Path, logical_bytes: int) -> list[str]:
    """Human-readable semantics for 4 GiB evidence logs (no secrets)."""
    canonical_zero = input_path.name == "zero4g.bin" and logical_bytes == _EXPECTED_BYTES
    block: list[str] = [
        "",
        "--- 4 GiB evidence semantics ---",
        f"Logical file size: {logical_bytes} bytes (4 * 1024**3).",
        "Streaming SHA-256 in this log digests the full logical byte sequence (sparse all-zero regions still read as zeros).",
        "Approach A and Approach B transfers stream the entire logical payload end-to-end.",
        "The assignment allows a 4 GiB file of random bytes or all-zero bytes; this repo's canonical zero4g.bin is logically all-zero for a deterministic digest.",
    ]
    if canonical_zero:
        block.append(
            "zero4g.bin (canonical): logical sparse all-zero 4 GiB when created per README (e.g. NTFS SetLength); "
            "reuse that file for evidence—do not regenerate as a dense non-sparse rewrite, do not substitute random-bytes payloads for this checklist, "
            "and avoid re-running dd over an existing correct file if that would rewrite the whole object."
        )
    return block


def _bootstrap_imports() -> None:
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))


def _streaming_sha256_hex(path: Path) -> tuple[str, int]:
    _bootstrap_imports()
    from common.hashing import sha256_hex_digest_file

    digest = sha256_hex_digest_file(path)
    size = path.stat().st_size
    return digest.lower(), size


def _ensure_input(path: Path, expected: int) -> int:
    if not path.is_file():
        raise SystemExit(f"ERROR: input not found or not a file: {path.resolve()}")
    size = path.stat().st_size
    if size != expected:
        raise SystemExit(f"ERROR: expected exactly {expected} bytes, got {size} ({path})")
    return size


def _timestamp_slug() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")


def _write_log(evidence_dir: Path, lines: list[str]) -> Path:
    evidence_dir.mkdir(parents=True, exist_ok=True)
    out = evidence_dir / f"transfer_evidence_{_timestamp_slug()}.txt"
    out.write_text("".join(f"{ln}\n" for ln in lines), encoding="utf-8")
    return out


def _run_transfer(
    *,
    recv_cmd: list[str],
    send_cmd: list[str],
    timeout_sec: float | None,
    startup_delay: float,
) -> tuple[int, int, str, str]:
    proc_recv = subprocess.Popen(
        recv_cmd,
        cwd=REPO_ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    time.sleep(startup_delay)
    if proc_recv.poll() is not None:
        early = proc_recv.stdout.read() if proc_recv.stdout else ""
        raise RuntimeError(f"receiver exited before sender started (exit {proc_recv.returncode})\n{early}")

    send_kw: dict = {
        "cwd": REPO_ROOT,
        "capture_output": True,
        "text": True,
        "encoding": "utf-8",
        "errors": "replace",
    }
    if timeout_sec and timeout_sec > 0:
        send_kw["timeout"] = timeout_sec

    proc_send = subprocess.run(send_cmd, **send_kw)
    recv_out_r: str | None = None
    recv_kw: dict = {}
    if timeout_sec and timeout_sec > 0:
        recv_kw["timeout"] = timeout_sec
    recv_out_r, _ = proc_recv.communicate(**recv_kw)

    sout = ((proc_send.stdout or "") + (proc_send.stderr or "")).strip()
    recv_log = (recv_out_r or "").strip()
    return proc_recv.returncode, proc_send.returncode, recv_log, sout


def _repo_rel(p: Path) -> Path:
    try:
        return p.relative_to(REPO_ROOT)
    except ValueError:
        return p


def _manual_command_template(
    *,
    input_path: Path,
    remote_name: str,
    port_a: int,
    port_b: int,
    out_a: Path,
    out_b: Path,
) -> list[str]:
    return [
        "MANUAL COMMAND TEMPLATE (run from repo root after venv activate)",
        "",
        "--- Approach A (terminal 1) ---",
        f"python approach-a-mtls/receiver.py --host 127.0.0.1 --port {port_a} --output-dir {out_a.as_posix()}",
        "",
        "--- Approach A (terminal 2) ---",
        (
            "python approach-a-mtls/sender.py --host 127.0.0.1 "
            f"--port {port_a} --file {input_path.as_posix()} --remote-name {remote_name}"
        ),
        "",
        "--- Approach B (terminal 1) ---",
        (
            "python approach-b-envelope/receiver.py --host 127.0.0.1 "
            f"--port {port_b} --keys-dir approach-b-envelope/keys --output-dir {out_b.as_posix()}"
        ),
        "",
        "--- Approach B (terminal 2) ---",
        (
            "python approach-b-envelope/sender.py --host 127.0.0.1 "
            f"--port {port_b} --keys-dir approach-b-envelope/keys "
            f"--file {input_path.as_posix()} --remote-name {remote_name}"
        ),
        "",
        "After both transfers, record hashes with:",
        f"  python scripts/collect_evidence.py --input {input_path.as_posix()} \\",
        f"    --approach-a-output {out_a.joinpath(remote_name).as_posix()} \\",
        f"    --approach-b-output {out_b.joinpath(remote_name).as_posix()}",
        "",
    ]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input",
        type=Path,
        default=REPO_ROOT / "zero4g.bin",
        help="Path to the 4 GiB file (default: ./zero4g.bin from repo root).",
    )
    parser.add_argument(
        "--expected-bytes",
        type=int,
        default=_EXPECTED_BYTES,
        help=f"Exact required size in bytes (default {_EXPECTED_BYTES}).",
    )
    parser.add_argument(
        "--evidence-dir",
        type=Path,
        default=REPO_ROOT / "evidence",
        help="Directory for transfer_evidence_*.txt logs.",
    )
    parser.add_argument(
        "--out-a",
        type=Path,
        default=REPO_ROOT / "evidence" / "received-a-4gb",
        help="Approach A receiver --output-dir (isolated under evidence/).",
    )
    parser.add_argument(
        "--out-b",
        type=Path,
        default=REPO_ROOT / "evidence" / "received-b-4gb",
        help="Approach B receiver --output-dir.",
    )
    parser.add_argument("--port-a", type=int, default=28443, help="Ephemeral port for Approach A.")
    parser.add_argument("--port-b", type=int, default=29443, help="Ephemeral port for Approach B.")
    parser.add_argument(
        "--timeout-sec",
        type=float,
        default=0.0,
        help="Per-phase timeout (sender + receiver wait). 0 = unlimited (recommended for 4 GiB).",
    )
    parser.add_argument(
        "--startup-delay",
        type=float,
        default=1.0,
        help="Seconds to wait after starting receiver before starting sender.",
    )
    parser.add_argument(
        "--no-transfers",
        action="store_true",
        help="Only verify size + input SHA-256 and write log with manual command template.",
    )
    args = parser.parse_args(argv)

    input_path: Path = args.input.expanduser()
    if not input_path.is_absolute():
        input_path = (REPO_ROOT / input_path).resolve()
    evidence_dir = args.evidence_dir.resolve()
    out_a = args.out_a.expanduser().resolve()
    out_b = args.out_b.expanduser().resolve()

    ts = datetime.now(UTC).isoformat()
    lines: list[str] = [
        f"transfer_evidence generated={ts}",
        f"platform={platform.platform()}",
        f"python={sys.version.split()[0]} executable={sys.executable}",
        f"repo_root={REPO_ROOT}",
        f"input_path={input_path}",
    ]

    _ensure_input(input_path, int(args.expected_bytes))
    input_hex, isize = _streaming_sha256_hex(input_path)
    lines += [
        "",
        f"input_bytes={isize}",
        f"INPUT_SHA256={input_hex}",
    ]
    lines.extend(_four_gib_semantic_log_lines(input_path=input_path, logical_bytes=isize))

    remote_name = input_path.name
    recv_a_final = out_a / remote_name
    recv_b_final = out_b / remote_name
    tout = args.timeout_sec if args.timeout_sec > 0 else None

    if args.no_transfers:
        lines.append("")
        lines.append("MODE=no_transfers (subprocess transfers skipped)")
        lines.extend(
            _manual_command_template(
                input_path=_repo_rel(input_path),
                remote_name=remote_name,
                port_a=int(args.port_a),
                port_b=int(args.port_b),
                out_a=_repo_rel(out_a),
                out_b=_repo_rel(out_b),
            )
        )
        lines.append("Hashes for received outputs: not computed (manual mode).")
        log_path = _write_log(evidence_dir, lines)
        print(f"Wrote {log_path}")
        return 0

    recv_py = sys.executable
    base_recv_a = [
        recv_py,
        str(REPO_ROOT / "approach-a-mtls" / "receiver.py"),
        "--host",
        "127.0.0.1",
        "--port",
        str(int(args.port_a)),
        "--output-dir",
        str(out_a),
    ]
    send_a = [
        recv_py,
        str(REPO_ROOT / "approach-a-mtls" / "sender.py"),
        "--host",
        "127.0.0.1",
        "--port",
        str(int(args.port_a)),
        "--file",
        str(input_path),
        "--remote-name",
        remote_name,
    ]

    lines += ["", "--- Approach A (automated subprocess) ---", f"receiver_cmd={' '.join(base_recv_a)}", f"sender_cmd={' '.join(send_a)}"]

    out_a.mkdir(parents=True, exist_ok=True)
    out_b.mkdir(parents=True, exist_ok=True)

    try:
        rc_r, rc_s, slog_r, slog_s = _run_transfer(
            recv_cmd=base_recv_a,
            send_cmd=send_a,
            timeout_sec=tout,
            startup_delay=float(args.startup_delay),
        )
    except Exception as exc:
        lines.append(f"Approach_A_ERROR={exc!r}")
        log_path = _write_log(evidence_dir, lines)
        print(f"ERROR during Approach A transfer. Log: {log_path}", file=sys.stderr)
        return 1

    lines += ["receiver_exit_code=" + str(rc_r), "sender_exit_code=" + str(rc_s), "", "[receiver_stdout]", slog_r or "(empty)", "", "[sender_stdout+stderr]", slog_s or "(empty)"]

    if rc_r != 0 or rc_s != 0:
        lines.append("Approach_A_STATUS=FAILED_nonzero_exit")
        hex_a = "N/A"
    else:
        if not recv_a_final.is_file():
            lines.append(f"Approach_A_STATUS=MISSING_OUTPUT expected={recv_a_final}")
            hex_a = "N/A"
        else:
            hex_a, sa = _streaming_sha256_hex(recv_a_final)
            lines += ["", f"Approach_A_output_bytes={sa}", f"APPROACH_A_OUTPUT_SHA256={hex_a}", f"A_match={'PASS' if hex_a == input_hex else 'FAIL'}"]

    base_recv_b = [
        recv_py,
        str(REPO_ROOT / "approach-b-envelope" / "receiver.py"),
        "--host",
        "127.0.0.1",
        "--port",
        str(int(args.port_b)),
        "--keys-dir",
        str(REPO_ROOT / "approach-b-envelope" / "keys"),
        "--output-dir",
        str(out_b),
    ]
    send_b = [
        recv_py,
        str(REPO_ROOT / "approach-b-envelope" / "sender.py"),
        "--host",
        "127.0.0.1",
        "--port",
        str(int(args.port_b)),
        "--keys-dir",
        str(REPO_ROOT / "approach-b-envelope" / "keys"),
        "--file",
        str(input_path),
        "--remote-name",
        remote_name,
    ]

    lines += ["", "--- Approach B (automated subprocess) ---", f"receiver_cmd={' '.join(base_recv_b)}", f"sender_cmd={' '.join(send_b)}"]

    if rc_r != 0 or rc_s != 0 or not recv_a_final.is_file():
        reason: list[str] = []
        if rc_r != 0 or rc_s != 0:
            reason.append("nonzero_exit")
        if not recv_a_final.is_file():
            reason.append("missing_output_file")
        lines += [f"Approach_B_STATUS=skipped ({'+'.join(reason) or 'unknown'})"]
        log_path = _write_log(evidence_dir, lines)
        print(f"Wrote {log_path} (Approach B skipped)")
        return 1

    try:
        rc_r2, rc_s2, slog_r2, slog_s2 = _run_transfer(
            recv_cmd=base_recv_b,
            send_cmd=send_b,
            timeout_sec=tout,
            startup_delay=float(args.startup_delay),
        )
    except Exception as exc:
        lines.append(f"Approach_B_ERROR={exc!r}")
        log_path = _write_log(evidence_dir, lines)
        print(f"ERROR during Approach B transfer. Log: {log_path}", file=sys.stderr)
        return 1

    lines += ["receiver_exit_code=" + str(rc_r2), "sender_exit_code=" + str(rc_s2), "", "[receiver_stdout]", slog_r2 or "(empty)", "", "[sender_stdout+stderr]", slog_s2 or "(empty)"]

    if rc_r2 != 0 or rc_s2 != 0:
        lines.append("Approach_B_STATUS=FAILED_nonzero_exit")
        hex_b = "N/A"
    elif not recv_b_final.is_file():
        lines.append(f"Approach_B_STATUS=MISSING_OUTPUT expected={recv_b_final}")
        hex_b = "N/A"
    else:
        hex_b, sb = _streaming_sha256_hex(recv_b_final)
        lines += ["", f"Approach_B_output_bytes={sb}", f"APPROACH_B_OUTPUT_SHA256={hex_b}", f"B_match={'PASS' if hex_b == input_hex else 'FAIL'}"]

    lines.append("")
    lines.append("SUMMARY:")
    lines.append(f"  INPUT_SHA256={input_hex}")
    lines.append(f"  Approach A output match: {hex_a == input_hex if hex_a != 'N/A' else 'unknown'}")
    lines.append(f"  Approach B output match: {hex_b == input_hex if hex_b != 'N/A' else 'unknown'}")

    log_path = _write_log(evidence_dir, lines)
    print(textwrap.fill(f"Wrote evidence log: {log_path}", 100))
    all_ok = (
        hex_a == input_hex
        and hex_b == input_hex
        and hex_a != "N/A"
        and hex_b != "N/A"
    )
    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
