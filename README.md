# Secure large-file transfer (CMPE272)

## Project overview

This repository implements **two different ways** to move a **multi‑gigabyte file** over TCP with **bounded memory** (chunked reads/writes), **mutual peer authentication**, and **fail‑closed disk semantics**: the final file path appears only after **SHA‑256** over the full plaintext matches what was declared before the payload.

| Approach | Transport | Mutual authentication | File confidentiality & integrity |
|----------|-------------|-------------------------|----------------------------------|
| **A — mTLS** | TCP + **TLS 1.2** (`ssl`) | X.509 client + server certificates signed by a **local CA** | AEAD record ciphers only (**AES‑GCM** / **ChaCha20‑Poly1305** via `TLS12_MT_ALLOWED_CIPHER_LIST`); plaintext chunks inside the tunnel |
| **B — envelope** | **Plain TCP** (no TLS) | **Ed25519** signatures on a handshake transcript + signed **manifest** | **ChaCha20‑Poly1305** or **AES‑256‑GCM** per chunk; **X25519** static + ephemeral ECDH + **HKDF** for the file key |

Shared library code lives in **`common/`** (streaming SHA‑256, length‑prefixed JSON/binary framing, `*.part` writers, atomic `os.replace`). Cryptography uses the **`cryptography`** package where needed; hashing uses **`hashlib`** (stdlib). **No custom ciphers** and **no secrets in source** — keys and certs are generated locally and listed in **`.gitignore`**.

**Further reading:** [`DESIGN.md`](DESIGN.md) (protocols, threat model, CIAA mapping §2.4), [`TESTING.md`](TESTING.md) (failure demos), [`AI_NOTES.md`](AI_NOTES.md) (tooling transparency).

### Assignment rubric alignment (quick map)

| Rubric criterion (100 pts) | Evidence in this repo |
|----------------------------|------------------------|
| **Two distinct approaches (25)** — *both transfer a large file end-to-end with hash verification; architecturally different, not cosmetic* | **Architecture:** **A** = TCP + **TLS 1.2 mTLS** + cleartext framing **inside** the TLS tunnel; **B** = **plain TCP** + **Ed25519** transcript/manifest + **X25519/HKDF** + **per-chunk AEAD** (overview table above). **Large file (assignment scale):** **`README.md`** walks **`zero4g.bin`** (**logical 4 GiB**, `4 × 1024³` bytes) through **A** then **B** with **streaming SHA-256** checks; **`scripts/run_4gb_evidence.py`** / **`collect_evidence.py`** record hashes in **`evidence/transfer_evidence_*.txt`**. **Fast clone check (≪ 4 GiB):** **`scripts/smoke_test_all.py`** exercises **both** stacks on **1 MiB** with the same verify-before-rename semantics. |
| **CIAA coverage (25)** — *each property tied to a named mechanism; honest threat model matching code* | **`DESIGN.md` §2** (threat-by-threat for A and B) and **§2.4** (CIAA→mechanism tables: **C**onfidentiality, **I**ntegrity, **A**uthenticity, **A**vailability / fail-safe). Limits (e.g. metadata leakage on B, broker out of scope) are stated explicitly. |
| **Cryptographic correctness (20)** — *AEAD used correctly; no nonce reuse; no hand-rolled crypto; fail closed on verify failure* | AEAD-only symmetric paths; **no** raw CBC; Approach **B** chunk **nonces** from **`(session_id, chunk_index)`**; **SHA-256** over full plaintext before rename; **`cryptography`** + **`hashlib`** only. Receivers **fail closed** (no trusted final file) on handshake/TLS, signature, AEAD, size, or digest mismatch — see **`tests/test_*_security_negative.py`** and **`TESTING.md`**. |
| **Code quality & runnability (10)** — *clean structure, named constants, no hardcoded secrets; fresh clone runnable quickly via README* | **`common.constants`** (e.g. **`TLS12_MT_ALLOWED_CIPHER_LIST`**), chunked I/O, **no** PEM/passwords in source (generated material listed in **`.gitignore`**). **Typical fresh clone:** venv + **`pip install -r requirements.txt`** (fences in **Installation**) then **`scripts/smoke_test_all.py`** or **`python -m unittest discover -s tests -v`** (**§Quick smoke test** / **`TESTING.md`**) is usually **well under ~5 minutes** on classroom hardware (no 4 GiB file required for that path). Full **4 GiB** steps are later in this README. |
| **AI collaboration (15)** — *honest, specific; human directed the work; at least one example of catching/correcting assistant output* | **`AI_NOTES.md`**: tooling disclosure, what was human-reviewed, **directed collaboration** (not rubber-stamping), a **concrete doc fix** (placeholder paths → real commands), and **rejection of insecure “debug” shortcuts** for Approach **B** verification. |
| **Stretch (5)** — *quality over quantity; e.g. throughput, forward secrecy, resumability/broker discussion* | **Throughput:** payload-phase lines — **`README.md` → 4 GiB evidence checklist → Throughput measurement**. **Forward secrecy / cipher caveats:** **`DESIGN.md` §2.4.2–2.4.3**. **Resumability:** **not** implemented — **fail-safe** minimum only (**DESIGN.md** §1). **Untrusted broker:** **out of scope** (**DESIGN.md** §2.4 stretch table). |

**You still owe (not in repo):** a **2–3 minute demo recording** (or live walkthrough) showing both approaches on a real **4 GiB** file and hash verification, per deliverable §7 item 13.

---

## Repository layout

| Path | Purpose |
|------|---------|
| `common/` | Streaming file I/O, SHA‑256, temp/part files, TCP helpers, length‑prefixed framing. |
| `approach-a-mtls/` | `generate_certs.py`, `receiver.py`, `sender.py` — mutual TLS file transfer. |
| `approach-b-envelope/` | `generate_keys.py`, `receiver.py`, `sender.py` — plain TCP + envelope crypto (`DESIGN.md` §5). |
| `scripts/` | **`run_4gb_evidence.py`**, **`collect_evidence.py`**, **`smoke_test_all.py`**, **`failsafe_demo.py`**, `make_test_file.py`, tamper relay, wrong‑SHA TLS client; see **`TESTING.md`** and **§4 GiB evidence checklist** below. |
| `tests/` | `unittest` regressions (**smoke**, **Approach A TLS policy / handshake negatives**, **Approach B signing / AEAD / chunk negatives**). Run **`python -m unittest discover -s tests -v`**. |
| `DESIGN.md` | Architecture, algorithms, threat tables, normative Approach B wire format. |
| `TESTING.md` | **Exact commands** for tampering, wrong CA/keys, **fail-safe demos**, SHA mismatch. |
| `AI_NOTES.md` | What was AI‑assisted vs human‑reviewed. |
| `requirements.txt` | `pip` dependencies (`cryptography`). |

---

## Installation

Use **Python 3.10+** (tested with 3.11). From the **repository root**:

### Windows PowerShell

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

If script execution is blocked: `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` once, or call `.\.venv\Scripts\python.exe` without activating.

### Unix (bash / zsh)

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

All commands below assume the **virtual environment is activated** and the **current directory is the repository root**.

**Operating system:** Alternate **Windows** and **Unix** fences **only inside the same shell family** (`python …` vs `python3 …`, backslashes vs slashes). **`Failure tests`** and **`Fail-safe demo`** expose **Unix variants** beside PowerShell — pick one OS per run so copy‑paste stays valid without editing paths manually.

---

## Quick smoke test (~1 MiB, Approach A + Approach B)

After install, **`scripts/smoke_test_all.py`** runs a bounded regression on **both** stacks using a **`1 MiB`** payload in **system temp**, **streaming** hashes (no giant buffers), **`generate_certs.py` / `generate_keys.py`** only if PEMs are **missing**, and **timeouts** per phase (`--phase-timeout`; use **`0`** to disable timeouts—may hang):

**Windows**

```powershell
python scripts\smoke_test_all.py
```

**Unix**

```bash
python3 scripts/smoke_test_all.py
```

Expect **`APPROACH_A: PASS`** / **`APPROACH_B: PASS`** and **`OVERALL: PASS`**. Change payload size (**`--size`**) or ports (**`--port-a`**, **`--port-b`**) if **`48543` / `49543`** collide with local services.

---

## Automated security-negative regressions (`unittest`)

CI-style checks—not a substitute for the manual tamper flows in **`TESTING.md`**, but they repeatedly prove **authentication and integrity failure modes stay closed**:

**Windows**

```powershell
python -m unittest discover -s tests -v
```

**Unix**

```bash
python3 -m unittest discover -s tests -v
```

This drives **`tests/test_approach_a_security_negative.py`** (no `CERT_NONE` / insecure hostname toggles on the client; wrong CA handshake; withheld client certificate) and **`tests/test_approach_b_security_negative.py`** (wrong trusted sender Ed25519 public key, flipped manifest/chunk ciphertext, bad or replayed chunk indices, plus unit checks on AEAD nonce and associated data bindings).

---

## Generate a 4 GiB test file

**Canonical filename in this README:** **`zero4g.bin`** at the **repository root**. All §4 GiB examples below use **`--file zero4g.bin`**, **`--remote-name zero4g.bin`**, and received paths **`received\zero4g.bin`** / **`received-b\zero4g.bin`** so you can run steps in order copy‑paste style. *(The course PDF sometimes shows **`test_4gb.bin`** as an illustration name — that file is identical in role; just replace the basename everywhere consistently.)*

**Reuse an existing file for evidence:** If **`zero4g.bin`** is already **exactly `4294967296` bytes** (for example a **sparse**, **zero‑filled** NTFS file from **`FileStream.SetLength`** below), use it for **`scripts/run_4gb_evidence.py`** and the manual §4 GiB steps. **Do not** regenerate it as a **non‑sparse** dense file, **do not** switch this workflow to **random** payload bytes (the assignment allows **random or all‑zero** logical content; this repo standardizes on **all‑zero** for a **deterministic** SHA‑256), and **do not** re‑invoke **`dd`** in a way that **rewrites the entire 4 GiB** when a correct file is already present.

**Logical size, hashing, and transfer:** The on‑disk object’s **logical size** is **`4294967296`** bytes (4 GiB, i.e. `4 * 1024**3` in Python). **`common.hashing.sha256_hex_digest_file`** and the senders/receivers **stream every logical byte** in order; **SHA‑256** is over that **full logical** sequence (sparse regions still read as zeros). **Approach A** and **Approach B** each move the **complete logical 4 GiB** over the wire.

**Do not** use the rubric’s sample `python -c "open(...).write(b'\\0'*4*1024*1024*1024)"` one-liner: it builds a **4 GiB byte string in RAM** and can exhaust memory.

**Pick exactly one creation path** for your OS and situation—**do not** run the Windows fence, then the Unix fence, then the streaming Python fence in sequence (that wastes time and can replace a good sparse file with a long dense rewrite). Choices below:

1. **Windows (NTFS):** sparse **`FileStream.SetLength`** — fastest when you need a new file.  
2. **Unix / WSL / Git Bash:** **`dd`** — **first creation only**; skip if **`zero4g.bin`** is already correct.  
3. **Any OS:** **`scripts/make_test_file.py --pattern-byte 0`** — portable streaming zeros (slow).

All three yield an **all‑zero logical** file (same SHA‑256 as **`dd`** from `/dev/zero`).

### Windows PowerShell (sparse file; native NTFS)

Do **not** use `dd` in Windows PowerShell (that is for Unix/WSL). Use .NET:

```powershell
$z = "zero4g.bin"
$fs = [System.IO.File]::Create($z)
$fs.SetLength([int64]4294967296)
$fs.Close()
```

### Unix (Linux, macOS, WSL, or Git Bash)

**First creation only:** if **`zero4g.bin`** already exists with the correct size, **skip** this step—re‑running **`dd`** would rewrite the **entire 4 GiB** on typical filesystems (slow and unnecessary).

```bash
dd if=/dev/zero of=zero4g.bin bs=1M count=4096 status=progress
```

### Cross‑platform streaming write (slow but portable; zeros only)

Repeated 1 MiB block writes — **does not buffer 4 GiB in RAM**. Use **`--pattern-byte 0`** so the SHA‑256 matches the sparse/dd **all‑zero** files above (`make_test_file`’s default pattern is **`0x5A`**, which would **not** match).

```powershell
python scripts\make_test_file.py --size 4294967296 --output zero4g.bin --pattern-byte 0
```

```bash
python3 scripts/make_test_file.py --size 4294967296 --output zero4g.bin --pattern-byte 0
```

---

## Hash `zero4g.bin` **before transfers** (optional preflight)

**Only** fingerprints the **repository-root** `--file` blob you generated above. **`received/`** outputs do **not** exist until **§Approach A**, step **3** succeeds — do **not** paste received-path commands here yet (they appear inside **§Approach A → 4)** and **§Approach B → 3)** only).

The helper streams in chunks; it does **not** load **4 GiB** into RAM. For a **sparse** **`zero4g.bin`**, the digest is still over the **full logical 4 GiB** of zero bytes.

**Windows**

```powershell
python -c "import sys; sys.path.insert(0,'.'); from pathlib import Path; from common.hashing import sha256_hex_digest_file; print(sha256_hex_digest_file(Path(r'zero4g.bin')))"
```

**Unix**

```bash
python -c "import sys; sys.path.insert(0,'.'); from pathlib import Path; from common.hashing import sha256_hex_digest_file; print(sha256_hex_digest_file(Path('zero4g.bin')))"
```

(Optional: confirm with **`Get-FileHash zero4g.bin -Algorithm SHA256`** or **`sha256sum zero4g.bin`** if you prefer tools outside Python.)

---

## Hash received output **after** each approach (later steps)

Paste these **only immediately after** the matching transfer finishes — **never** skip ahead while reading top‑to‑bottom.

| Moment | Plain English path |
|--------|---------------------|
| After **§Approach A**, §**4)** | **`received\zero4g.bin`** (Windows) / **`received/zero4g.bin`** (Unix) |
| After **§Approach B**, §**2)** **Unix/Windows digest compare** | **`received-b/b_approach_b_e2e_payload.bin`** (+ repo-root **`b_approach_b_e2e_payload.bin`**) — commands are inlined in §2 |
| After **§Approach B**, §**3)** (**4 GiB sender finished**) | **`received-b\zero4g.bin`** / **`received-b/zero4g.bin`** |

Exact one‑liners: **§Approach A → 4)**; **§Approach B → 2)** (tiny payload compare); **§Approach B → 3) Verify**.

---

## Approach A — exact commands (mTLS)

### 1) Generate local certificates

**Windows**

```powershell
python approach-a-mtls\generate_certs.py --force
```

**Unix**

```bash
python3 approach-a-mtls/generate_certs.py --force
```

PEMs are written under `approach-a-mtls/certs/` (ignored by git). Optional: encrypt private keys at rest with `MTLS_KEY_ENCRYPTION_PASSWORD` (see `python approach-a-mtls\generate_certs.py --help`).

### 2) Receiver (terminal 1)

**Windows**

```powershell
python approach-a-mtls\receiver.py --host 127.0.0.1 --port 8443 --output-dir received
```

**Unix**

```bash
python3 approach-a-mtls/receiver.py --host 127.0.0.1 --port 8443 --output-dir received
```

### 3) Sender (terminal 2) — 4 GiB example

**Windows**

```powershell
python approach-a-mtls\sender.py --host 127.0.0.1 --port 8443 --file zero4g.bin --remote-name zero4g.bin
```

**Unix**

```bash
python3 approach-a-mtls/sender.py --host 127.0.0.1 --port 8443 --file zero4g.bin --remote-name zero4g.bin
```

Defaults for `--ca-cert`, `--server-cert`, `--server-key` (receiver) and `--ca-cert`, `--client-cert`, `--client-key` (sender) point at `approach-a-mtls/certs/`.

### 4) Verify received digest

Paste **after step 3** completes. Digest must equal the **sender’s printed `SHA‑256 (streaming): …`** line and the optional **preflight** hash from **§Hash `zero4g.bin`** (all‑zeros file → deterministic).

**Windows**

```powershell
python -c "import sys; sys.path.insert(0,'.'); from pathlib import Path; from common.hashing import sha256_hex_digest_file; print(sha256_hex_digest_file(Path(r'received\zero4g.bin')))"
```

**Unix**

```bash
python -c "import sys; sys.path.insert(0,'.'); from pathlib import Path; from common.hashing import sha256_hex_digest_file; print(sha256_hex_digest_file(Path('received/zero4g.bin')))"
```

---

## Approach B — exact commands (envelope)

### 1) Generate envelope keys

**Windows**

```powershell
python approach-b-envelope\generate_keys.py --force
```

**Unix**

```bash
python3 approach-b-envelope/generate_keys.py --force
```

PEMs go to `approach-b-envelope/keys/` (git‑ignored).

### 2) Small end‑to‑end check (fixed payload name)

Creates **`b_approach_b_e2e_payload.bin`** at the repo root and receives **`received-b/b_approach_b_e2e_payload.bin`** automatically — **`--remote-name` default** is basename of **`--file`**, so names stay aligned without renaming.

**Windows — Terminal 1**

```powershell
python -c "from pathlib import Path; Path('b_approach_b_e2e_payload.bin').write_bytes(b'CMPE272 Approach B E2E test payload\n')"
python approach-b-envelope\receiver.py --host 127.0.0.1 --port 9443 --keys-dir approach-b-envelope\keys --output-dir received-b
```

**Windows — Terminal 2**

```powershell
python approach-b-envelope\sender.py --host 127.0.0.1 --port 9443 --keys-dir approach-b-envelope\keys --file .\b_approach_b_e2e_payload.bin
```

**Windows — Compare digests**

```powershell
python -c "import sys; sys.path.insert(0,'.'); from pathlib import Path; from common.hashing import sha256_hex_digest_file; p=Path('b_approach_b_e2e_payload.bin'); r=Path(r'received-b\b_approach_b_e2e_payload.bin'); print('source   ', sha256_hex_digest_file(p)); print('received ', sha256_hex_digest_file(r))"
```

**Unix — Terminal 1**

```bash
python3 -c "from pathlib import Path; Path('b_approach_b_e2e_payload.bin').write_bytes(b'CMPE272 Approach B E2E test payload\n')"
python3 approach-b-envelope/receiver.py --host 127.0.0.1 --port 9443 --keys-dir approach-b-envelope/keys --output-dir received-b
```

**Unix — Terminal 2**

```bash
python3 approach-b-envelope/sender.py --host 127.0.0.1 --port 9443 --keys-dir approach-b-envelope/keys --file b_approach_b_e2e_payload.bin
```

**Unix — Compare digests**

```bash
python3 -c "import sys; sys.path.insert(0,'.'); from pathlib import Path; from common.hashing import sha256_hex_digest_file; p=Path('b_approach_b_e2e_payload.bin'); r=Path('received-b/b_approach_b_e2e_payload.bin'); print('source   ', sha256_hex_digest_file(p)); print('received ', sha256_hex_digest_file(r))"
```

### 3) Large file (4 GiB) — same `zero4g.bin` as Approach A

The §2 receiver exits after the small transfer finishes. **Start a new receiver** below (same **`9443`** / **`received-b`** paths as §2 — no manual renames).

**Receiver**

**Windows**

```powershell
python approach-b-envelope\receiver.py --host 127.0.0.1 --port 9443 --keys-dir approach-b-envelope\keys --output-dir received-b
```

**Unix**

```bash
python3 approach-b-envelope/receiver.py --host 127.0.0.1 --port 9443 --keys-dir approach-b-envelope/keys --output-dir received-b
```

**Sender** (two passes over disk: hash then encrypt+send)

**Windows**

```powershell
python approach-b-envelope\sender.py --host 127.0.0.1 --port 9443 --keys-dir approach-b-envelope\keys --file zero4g.bin --remote-name zero4g.bin
```

**Unix**

```bash
python3 approach-b-envelope/sender.py --host 127.0.0.1 --port 9443 --keys-dir approach-b-envelope/keys --file zero4g.bin --remote-name zero4g.bin
```

**Verify** (**after** §3 Sender finishes)

**Windows**

```powershell
python -c "import sys; sys.path.insert(0,'.'); from pathlib import Path; from common.hashing import sha256_hex_digest_file; print(sha256_hex_digest_file(Path(r'received-b\zero4g.bin')))"
```

**Unix**

```bash
python -c "import sys; sys.path.insert(0,'.'); from pathlib import Path; from common.hashing import sha256_hex_digest_file; print(sha256_hex_digest_file(Path('received-b/zero4g.bin')))"
```

---

## Failure tests — exact commands (summary)

Full step‑by‑step scenarios (relay ports, `Test-Path` checks, wrong key dirs) are in **[`TESTING.md`](TESTING.md)**. Minimal copies:

| Demo | Windows command(s) |
|------|---------------------|
| **1 MiB payload** | `python scripts\make_test_file.py --size 1048576 --output testing_1mb.bin` |
| **A — wrong CA** | Sender: add `--ca-cert approach-a-mtls\certs\server-cert.pem` (leaf, not CA) |
| **A — SHA mismatch** | `python scripts\a_tls_send_wrong_metadata_sha.py --host 127.0.0.1 --port 8443 --file testing_1mb.bin --remote-name testing_1mb.bin` |
| **A — abort mid‑transfer** | **`README.md` → Fail-safe demo** (+ `scripts\failsafe_demo.py`) |
| **B — wrong sender Ed25519 pub on receiver** | See `TESTING.md` (`keys-alt` + `keys-wrong-demo` + `--keys-dir`) |
| **B — tamper manifest / sig / chunk** | `python scripts\b_tcp_relay_tamper.py --listen-port 9444 --upstream-port 9443 --mode first-chunk-byte` then sender `--port 9444` |

---

## Fail-safe demo

Demonstrates rubric §4.1 §8 wording: implementations must be **resumable or, at minimum, fail‑safe.** This codebase is **fail‑safe only**—no negotiated resume offsets. If the TCP session drops (or you kill the sender), the receiver **must not leave a basename that looks finished** unless **streaming SHA‑256 + full byte count** match after a complete ingest (`DESIGN.md` §1).

Use **distinct output dirs** below (`received-failsafe-demo/` …) so you do not collide with shorter classroom runs.

Fail‑safe demos **do not** need a **4 GiB** file. Use a **medium** payload (**128 MiB** or **512 MiB** are typical) so a **mid‑transfer interrupt** is easy to hit on fast loopback; **`scripts/failsafe_demo.py`** defaults to **8 MiB** (enough for CI) but on very fast machines you may need **`--size 134217728`** (128 MiB) or **`536870912`** (512 MiB) so the sender is killed before the file finishes.

**Suggested sizes**

| Goal | `--size` (bytes) | Notes |
|------|-----------------|--------|
| **128 MiB** | **`134217728`** | Lighter than 512 MiB; often enough for reliable scripted abort on fast localhost. |
| **512 MiB** | **`536870912`** | Comfortable classroom demo (~minutes to generate on slow disks). |
| **1 GiB** | **`1073741824`** | Same steps; longer create + transfer times. |

### Scripted smoke (recommended first)

**Windows**

```powershell
python scripts\failsafe_demo.py
```

**Unix**

```bash
python3 scripts/failsafe_demo.py
```

Creates an **> 1 MiB** deterministic payload under **temp** (default **8 MiB**), kills the Approach A / B sender **during** plaintext delivery (tracked via the first **`Sending:`** line showing enough uncompressed bytes remaining to avoid a trivial race), asserts **no** committed final file, then reruns **full transfers** until SHA‑256 matches. On **very fast** loopback, pass a **larger** **`--size`** (e.g. **`134217728`** or **`536870912`**) so the abort wins the race. Optional **`--kill-after`** pauses **after** that line (**> 0** often lets localhost finish the remainder before SIGKILL arrives—normally keep **`0`**).

### Manual choreography — Approach A (Windows PowerShell, 512 MiB)

Prereqs: **`python approach-a-mtls\generate_certs.py --force`** once (`certs/` populated).

Assume repository root **current directory.**

**1) Create a medium test file**

```powershell
python scripts\make_test_file.py --size 536870912 --output failsafe_demo_512m.bin
```

**2) Start the receiver** (Terminal 1 — process blocks on `accept`)

```powershell
python approach-a-mtls\receiver.py --host 127.0.0.1 --port 8443 --output-dir received-failsafe-demo
```

**3) Start the sender** (Terminal 2 — extra‑small TLS chunks **and** **`1 MiB` progress dots** give you readable `Sending:` lines on large files):

```powershell
python approach-a-mtls\sender.py --host 127.0.0.1 --port 8443 --file failsafe_demo_512m.bin `
  --remote-name failsafe_demo_512m.bin --chunk-size 65536 --progress-interval-mib 1
```

**4) Kill the sender mid‑transfer**

Use **Ctrl+C** in the **sender** terminal as soon as you see **`Sending:`** reporting **partial** progress (numerator < denominator).

**5) Trusted final output must NOT exist**

```powershell
Test-Path .\received-failsafe-demo\failsafe_demo_512m.bin
```

Expect **`False`**.

**6) Inspect only leftovers** (`*.part` / `.quarantine` / stray temp staging)

```powershell
Test-Path .\received-failsafe-demo\failsafe_demo_512m.bin.part
Get-ChildItem .\received-failsafe-demo\.quarantine -ErrorAction SilentlyContinue
```

Mid‑abort drops often delete `*.part` immediately; **`_fail()`**‑driven rejects may instead land under **`.quarantine/`**. Either way **the final basename** must remain absent until a verified full ingest.

**7) Restart cleanly from the beginning** — **Terminal 1:** receiver again; **Terminal 2:** sender again.

**Terminal 1**

```powershell
python approach-a-mtls\receiver.py --host 127.0.0.1 --port 8443 --output-dir received-failsafe-demo
```

**Terminal 2**

```powershell
python approach-a-mtls\sender.py --host 127.0.0.1 --port 8443 `
  --file failsafe_demo_512m.bin --remote-name failsafe_demo_512m.bin
```

**8) Confirm SHA‑256 matches** (streaming digest of source vs promoted receive path):

```powershell
python -c "import sys; sys.path.insert(0,'.'); from pathlib import Path; from common.hashing import sha256_hex_digest_file as h; s=h(Path(r'failsafe_demo_512m.bin')); d=h(Path(r'received-failsafe-demo\failsafe_demo_512m.bin')); assert s==d; print('SHA-256 OK', d)"
```

For **1 GiB**, replace **`536870912`** with **`1073741824`** and rename outputs consistently (e.g. **`failsafe_demo_1g.bin`**).

### Manual choreography — Approach B (Windows PowerShell, 512 MiB)

Prereqs: **`python approach-b-envelope\generate_keys.py --force`** (`keys/`).

**1)**

```powershell
python scripts\make_test_file.py --size 536870912 --output failsafe_demo_512m.bin
```

**2) Terminal 1 — receiver**

```powershell
python approach-b-envelope\receiver.py --host 127.0.0.1 --port 9443 --keys-dir approach-b-envelope\keys --output-dir received-b-failsafe-demo
```

**3) Terminal 2 — sender**

```powershell
python approach-b-envelope\sender.py --host 127.0.0.1 --port 9443 --keys-dir approach-b-envelope\keys `
  --file failsafe_demo_512m.bin --remote-name failsafe_demo_512m.bin `
  --chunk-plaintext-max 65536 --progress-interval-mib 1
```

**4)** **Ctrl+C** the sender mid‑flight after **`Sending:`** partial progress prints.

**5)**

```powershell
Test-Path .\received-b-failsafe-demo\failsafe_demo_512m.bin
```

Expect **`False`**.

**6)**

```powershell
Test-Path .\received-b-failsafe-demo\failsafe_demo_512m.bin.part
Get-ChildItem .\received-b-failsafe-demo\.quarantine -ErrorAction SilentlyContinue
```

**7) Full retry — Terminal 1 — receiver**

```powershell
python approach-b-envelope\receiver.py --host 127.0.0.1 --port 9443 --keys-dir approach-b-envelope\keys --output-dir received-b-failsafe-demo
```

**7b) Terminal 2 — sender** (defaults OK)

```powershell
python approach-b-envelope\sender.py --host 127.0.0.1 --port 9443 --keys-dir approach-b-envelope\keys `
  --file failsafe_demo_512m.bin --remote-name failsafe_demo_512m.bin
```

**8)**

```powershell
python -c "import sys; sys.path.insert(0,'.'); from pathlib import Path; from common.hashing import sha256_hex_digest_file as h; s=h(Path(r'failsafe_demo_512m.bin')); d=h(Path(r'received-b-failsafe-demo\failsafe_demo_512m.bin')); assert s==d; print('SHA-256 OK', d)"
```

### Manual choreography — Approach A (Unix / bash)

**1)**

```bash
python3 scripts/make_test_file.py --size 536870912 --output failsafe_demo_512m.bin
```

**2) Terminal 1 — receiver** (blocks until a client connects)

```bash
python3 approach-a-mtls/receiver.py --host 127.0.0.1 --port 8443 --output-dir received-failsafe-demo
```

**3) Terminal 2 — sender**

```bash
python3 approach-a-mtls/sender.py --host 127.0.0.1 --port 8443 \
  --file failsafe_demo_512m.bin --remote-name failsafe_demo_512m.bin \
  --chunk-size 65536 --progress-interval-mib 1
```

**4)** Ctrl+C sender once **`Sending:`** shows numerator < denominator.

**5)**

```bash
test ! -f received-failsafe-demo/failsafe_demo_512m.bin && echo "ok_final_absent"
```

**6)**

```bash
ls -la received-failsafe-demo/*.part 2>/dev/null || echo "no part file"
ls -la received-failsafe-demo/.quarantine 2>/dev/null || echo "no quarantine hits"
```

**7) Terminal 1 — receiver** (blocks until a client connects)

```bash
python3 approach-a-mtls/receiver.py --host 127.0.0.1 --port 8443 --output-dir received-failsafe-demo
```

**7b) Terminal 2 — sender**

```bash
python3 approach-a-mtls/sender.py --host 127.0.0.1 --port 8443 \
  --file failsafe_demo_512m.bin --remote-name failsafe_demo_512m.bin
```

**8)**

```bash
python3 -c "import sys; sys.path.insert(0,'.'); from pathlib import Path; from common.hashing import sha256_hex_digest_file as h; s=h(Path('failsafe_demo_512m.bin')); d=h(Path('received-failsafe-demo/failsafe_demo_512m.bin')); assert s==d; print('SHA-256 OK', d)"
```

### Manual choreography — Approach B (Unix / bash)

**1)**

```bash
python3 scripts/make_test_file.py --size 536870912 --output failsafe_demo_512m.bin
```

**2) Terminal 1 — receiver** (blocks until a client connects)

```bash
python3 approach-b-envelope/receiver.py --host 127.0.0.1 --port 9443 --keys-dir approach-b-envelope/keys --output-dir received-b-failsafe-demo
```

**3) Terminal 2 — sender**

```bash
python3 approach-b-envelope/sender.py --host 127.0.0.1 --port 9443 --keys-dir approach-b-envelope/keys \
  --file failsafe_demo_512m.bin --remote-name failsafe_demo_512m.bin \
  --chunk-plaintext-max 65536 --progress-interval-mib 1
```

**4)** Sender **Ctrl+C** mid-transfer.

**5–6)**

```bash
test ! -f received-b-failsafe-demo/failsafe_demo_512m.bin && echo ok_final_absent
ls -la received-b-failsafe-demo/*.part 2>/dev/null || echo "no part file"
ls -la received-b-failsafe-demo/.quarantine 2>/dev/null || true
```

**7–8)** After the full transfer completes, verify SHA‑256 (receiver in one terminal, sender in another — same pattern as steps **2–3**).

**Terminal 1 — receiver**

```bash
python3 approach-b-envelope/receiver.py --host 127.0.0.1 --port 9443 --keys-dir approach-b-envelope/keys --output-dir received-b-failsafe-demo
```

**Terminal 2 — sender**

```bash
python3 approach-b-envelope/sender.py --host 127.0.0.1 --port 9443 --keys-dir approach-b-envelope/keys \
  --file failsafe_demo_512m.bin --remote-name failsafe_demo_512m.bin
```

**SHA‑256 check** (run after both sides finish):

```bash
python3 -c "import sys; sys.path.insert(0,'.'); from pathlib import Path; from common.hashing import sha256_hex_digest_file as h; s=h(Path('failsafe_demo_512m.bin')); d=h(Path('received-b-failsafe-demo/failsafe_demo_512m.bin')); assert s==d; print('SHA-256 OK', d)"
```

### Faster 1 MiB dry‑run variant

Prefer **`scripts/failsafe_demo.py`** (automated abort + hash). For a handheld **tiny** rehearsal see **`TESTING.md`** → *Mid-transfer abort* (**`received\`**, **`received-b\`**, **`testing_1mb.bin`**, **`demo-abort*.bin`**).

---

## 4 GiB evidence checklist (grading / demo artifact)

Goal: reproducible proof that **`zero4g.bin`** has **logical size exactly 4 GiB** (**`4294967296`** bytes), both approaches **stream the full logical payload**, and **SHA‑256** (over those logical bytes) matches end‑to‑end. Prefer an **existing sparse, zero‑filled** **`zero4g.bin`** when it already meets that size; see **`scripts/run_4gb_evidence.py`** / **`scripts/collect_evidence.py`** logs for the same semantics block under **`--- 4 GiB evidence semantics ---`**.

### Prerequisites (once per machine)

| Step | Command |
|------|--------|
| venv + deps | **`Installation`** section above |
| `zero4g.bin` at repo root, **4294967296 bytes** | **`Generate a 4 GiB test file`** (pick **one** OS‑specific path) |
| certs | **§Approach A → 1)** — Windows / Unix fences above (`generate_certs.py --force`) |
| envelope keys | **§Approach B → 1)** — Windows / Unix fences above (`generate_keys.py --force`) |

### Saved artifacts for your submission zip

Keep at least:

1. **`evidence/transfer_evidence_*.txt`** — newest log from Option **A** or **B** below (plain text).
2. **Optional:** terminal screen‑capture or pasted stdout showing **SHA‑256** lines plus **payload** throughput (**`Send throughput:`** / **`Throughput:`** for A; **`Payload throughput:`** for B) — see **Throughput measurement** below.
3. **Do not** commit **`zero4g.bin`** (gitignored); graders expect you generated it locally per brief.

**What those evidence logs contain (and do not):** Logs from **`run_4gb_evidence.py`** and **`collect_evidence.py`** record **filenames**, **local paths** (inputs, `--output-dir`, `--keys-dir` *directories*), **sizes**, **timestamps**, **SHA‑256** digests of plaintext files, **throughput**, **PASS/FAIL**, and **subprocess stdout** that mirrors the receivers/senders (e.g. TLS client **CN**, AEAD **algorithm name**). For **4 GiB** runs they also include a fixed **`--- 4 GiB evidence semantics ---`** block (sparse **`zero4g.bin`**, logical size, assignment **random vs zero**, SHA over **logical** bytes, full **streamed** transfer). They are **not** designed to hold PEM private keys, certificate private bodies, symmetric **file** keys, **nonces**, or **passwords**—and you should still avoid pasting ad‑hoc secrets into terminals before capture. Including **`evidence/transfer_evidence_*.txt`** in a submission zip is appropriate when it comes from these scripts; if a course requires anonymity, you may scrub **absolute paths** (they can show your OS username) even though those paths are not cryptographic material.

### Option A — automated (`scripts/run_4gb_evidence.py`)

Orchestrates **Approach A → Approach B** with ephemeral ports (**28443** / **29443** default) and outputs **`evidence/received-a-4gb/`**, **`evidence/received-b-4gb/`** (avoids clobbering `received/` from the README walk‑through).

**Windows**

```powershell
python scripts\run_4gb_evidence.py --input zero4g.bin --timeout-sec 0
```

**Unix**

```bash
python3 scripts/run_4gb_evidence.py --input zero4g.bin --timeout-sec 0
```

- **`--timeout-sec 0`** = no wall‑clock limit (recommended for slow disks).
- Exit code **0** ⇒ log **`SUMMARY`** shows both outputs matching **`INPUT_SHA256`**.
- Log path: **`evidence/transfer_evidence_<UTC>.txt`** (printed on stdout).

**Preflight only** (verify size + streaming input hash + manual command template; **no** subprocess transfers):

**Windows**

```powershell
python scripts\run_4gb_evidence.py --no-transfers
```

**Unix**

```bash
python3 scripts/run_4gb_evidence.py --no-transfers
```

### Option B — manual README flow + `scripts/collect_evidence.py`

1. Run **§Approach A** and **§Approach B** large‑file steps in this README (defaults **`received/`**, **`received-b/`**, **`zero4g.bin`**).
2. Collate hashes:

**Windows**

```powershell
python scripts\collect_evidence.py --input zero4g.bin `
  --approach-a-output received\zero4g.bin `
  --approach-b-output received-b\zero4g.bin
```

**Unix**

```bash
python3 scripts/collect_evidence.py --input zero4g.bin \
  --approach-a-output received/zero4g.bin \
  --approach-b-output received-b/zero4g.bin
```

- Exit **0** only if both outputs exist, **byte sizes** match the source, and **SHA‑256** matches.
- Writes **`evidence/transfer_evidence_<UTC>.txt`** with **`OVERALL=PASS`**.

### Option C — hybrid (automated dirs + collect)

After **Option A** succeeds:

**Windows**

```powershell
python scripts\collect_evidence.py --input zero4g.bin `
  --approach-a-output evidence\received-a-4gb\zero4g.bin `
  --approach-b-output evidence\received-b-4gb\zero4g.bin
```

**Unix**

```bash
python3 scripts/collect_evidence.py --input zero4g.bin \
  --approach-a-output evidence/received-a-4gb/zero4g.bin \
  --approach-b-output evidence/received-b-4gb/zero4g.bin
```

### Throughput measurement (rubric stretch §4.2)

Both implementations print **payload‑phase** throughput in **MB/s (SI)** and **MiB/s (1024²)** after the file bytes finish (not the earlier hashing phase).

| Approach | Process | Line prefix to capture (stdout) |
|----------|---------|----------------------------------|
| **A** | **Sender** | **`Send throughput:`** — appears right after **`OK: sent …`** when the TLS payload completes. |
| **A** | **Receiver** | **`Throughput:`** — printed after **`OK: wrote …`** for the same transfer. |
| **B** | **Sender** | **`Payload throughput:`** — after **`OK: sent …`**. |
| **B** | **Receiver** | **`Payload throughput:`** — after **`OK: wrote …`**. |

**Recording during a demo:** scroll each terminal to the **last** throughput line for that run (sender and receiver each produce one line per successful transfer). Copy the two numbers **MB/s (SI)** and **MiB/s** into the table below or into your **`evidence/transfer_evidence_*.txt`** notes. If you use **`scripts/run_4gb_evidence.py`**, re‑open the script log file and paste the same four lines from the captured subprocess output.

**4 GiB results — template (fill from your machine)**

| Approach | Role | MB/s (SI) | MiB/s (1024²) |
|----------|------|-----------|---------------|
| A | Sender | | |
| A | Receiver | | |
| B | Sender | | |
| B | Receiver | | |

**Note:** Earlier **`Hashing:`** / **`SHA‑256 (streaming): … [… MB/s]`** lines measure the **pre‑flight hash pass** on disk, not the wire payload; use the table above for **stretch‑goal throughput** evidence.

### Forward secrecy and stretch non‑goals (summary)

- **Approach B:** each session uses fresh **X25519 ephemerals** in **HELLO1/HELLO2**; they are mixed with long‑term static X25519 keys into the HKDF input (**`DESIGN.md` §5.4**). **Compromising Ed25519 signing keys alone** does **not** reveal past **file** ciphertext: those keys authenticate transcripts/manifests; **file** confidentiality comes from the **X25519 / HKDF `file_key`**. **Caveats:** compromise of **long‑term X25519 private material** plus a **recorded handshake** can break confidentiality for that session; the stock code does **not** persist **`file_key`** or ephemerals to disk—**memory dumps**, **debug logging**, or **malware** could still leak them during a live transfer.
- **Approach A:** **TLS 1.2** is locked to **AEAD** suites via **`TLS12_MT_ALLOWED_CIPHER_LIST`** (**`common.constants`**); the list **prefers ECDHE‑RSA + AES‑GCM / ChaCha20‑Poly1305**, which gives **forward secrecy for application data** when that **ECDHE** suite is actually negotiated. **RSA‑key‑exchange** AEAD entries at the end of the list are a **compatibility fallback**—they **do not** provide the same **ECDHE‑style** forward secrecy; see **`DESIGN.md` §2.4** for the full discussion.
- **Not implemented (honest stretch gaps):** **true resumability** (assignment **fail‑safe** minimum instead; see **`DESIGN.md` §1**), **no broker / object store** (direct TCP only—untrusted‑broker threat handling is **out of scope**), **no rate‑limited automatic retry**.

Full rubric wording: **`DESIGN.md` §2.4** (CIAA + stretch table).

---

## Assignment checklist (course expectations)

- Two designs: **mTLS streaming** vs **plain TCP + application AEAD**.
- **Streaming:** chunk I/O only; never buffer the full ~4 GiB plaintext in memory.
- **Integrity:** SHA‑256 over final plaintext; mismatch → abort, no trusted final file.
- **Fail closed:** write `*.part` (or temp), verify, then `os.replace` only on success.
- **Mutual authentication:** TLS client+server certs vs Ed25519 transcript + manifest (see `DESIGN.md`).
- **Crypto:** stdlib `hashlib` / `ssl`; **`cryptography`** for Approach B AEAD and cert loading — **no custom ciphers**.
- **Secrets:** PEM paths or env‑based encryption at generation — **nothing hardcoded**.

---

## `common` package (short reference)

Scripts add the repo root to `sys.path`; you may also set `PYTHONPATH` to the repo root.

- **Chunks:** `iter_file_chunks(path, chunk_size=DEFAULT_CHUNK_SIZE_BYTES)` from `common.streaming`.
- **Hash:** `StreamingSha256`, `sha256_hex_digest_file`, `verify_file_sha256_hex` from `common.hashing`.
- **Disk:** `open_part_file`, `commit_verified_part`, `replace_with_final` from `common.temp_files` / `common.atomic_io`.
- **Wire:** `send_json_frame`, `recv_json_frame`, `send_binary_frame`, `recv_binary_frame` from `common.framing`.
- **Limits:** `DEFAULT_CHUNK_SIZE_BYTES` (1 MiB), `MAX_BINARY_PAYLOAD_BYTES` in `common.constants`.

---

## Implementation status

| Area | Status |
|------|--------|
| `common/` | Implemented |
| Approach A | `generate_certs.py`, `receiver.py`, `sender.py` |
| Approach B | `generate_keys.py`, `receiver.py`, `sender.py` |
| Failure demos | `scripts/`, `TESTING.md` |
| Evidence (4 GiB) | **`scripts/run_4gb_evidence.py`**, **`scripts/collect_evidence.py`**; logs under **`evidence/`** |
| Smoke (~1 MiB) | **`scripts/smoke_test_all.py`** (Approach A + B, temp dir, timeouts) |

---

## License / course policy

Add your course‑required license or attribution here when applicable.
