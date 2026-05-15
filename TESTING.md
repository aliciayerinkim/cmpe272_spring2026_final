# Manual failure demos and helper scripts

This project keeps **production code** in `approach-a-mtls/`, `approach-b-envelope/`, and `common/`. The **`scripts/`** helpers here exist only to make **classroom / demo failures** reproducible without editing core sources. For how these demos relate to the **course rubric** (CIAA tables, crypto correctness, stretch goals, AI disclosure), see **`README.md` → Assignment rubric alignment**, **`DESIGN.md` §2–§2.4**, and **`AI_NOTES.md`**.

## Automated regressions (`unittest`)

From the **repository root** (after `requirements.txt`), run every unit/integration test—including **security‑negative checks** that prove Approach A mTLS verification and Approach B Ed25519 / AEAD / chunk‑ordering defenses **fail closed**:

```powershell
python -m unittest discover -s tests -v
```

**Unix**: use `python3` instead of `python` if needed.

See `tests/test_approach_a_security_negative.py`, `tests/test_approach_b_security_negative.py`, and `tests/test_make_test_file_script.py` for specifics.

---

All manual failure-demo commands below use **Windows PowerShell** from the **repository root**. On Unix, use `python3`, path separators `/`, and shell equivalents for `Copy-Item` / `New-Item` / `Test-Path`.

## Shared: create a 1 MiB test file (fast, streaming write)

**Windows PowerShell**

```powershell
python scripts\make_test_file.py --size 1048576 --output testing_1mb.bin
```

**Unix**

```bash
python3 scripts/make_test_file.py --size 1048576 --output testing_1mb.bin
```

`testing_1mb.bin` is listed in `.gitignore` so it is not committed by accident.

## Fail-safe demo

Demonstrates assignment **fail-safe** wording: receivers **never** promote `*.part` to the final basename until **streaming SHA‑256** and declared **size** match after a complete ingest (**no negotiated resume offsets**). See **`README.md` § *Fail-safe demo*** for complete **numbered** instructions (medium **512 MiB / 1 GiB**, Windows + Unix, Approach A **and** B). Scripted check: **`scripts/failsafe_demo.py`** (see below).

### Scripted abort + hash sanity check

From repo root (**creates payloads under `%TEMP%` / `/tmp`; default ~8 MiB; requires > 1 MiB invariant**):

**Windows**

```powershell
python scripts\failsafe_demo.py
```

**Unix**

```bash
python3 scripts/failsafe_demo.py
```

The harness kills senders mid-payload (after detecting a plausible partial `Sending:` line with enough remainder), asserts **final basenames absent**, then reruns full transfers verifying **matching SHA‑256**.

### Pocket checklist (manual classroom run, 512 MiB)

Payload size **`536870912`** bytes (**1 GiB** → **`1073741824`**). Use **`failsafe_demo_512m.bin`**, **`--remote-name` matching** the basename, **`received-failsafe-demo/`** (Approach A) and **`received-b-failsafe-demo/`** (Approach B).

1. `python scripts\make_test_file.py --size 536870912 --output failsafe_demo_512m.bin` (**Unix**: `python3 … / …`).
2. Start receiver (**A**: `--port 8443`; **B**: `--port 9443`, add `--keys-dir approach-b-envelope\keys`).
3. Start sender with **small plaintext chunks plus frequent progress dots** (**A**: `--chunk-size 65536 --progress-interval-mib 1`; **B**: `--chunk-plaintext-max 65536 --progress-interval-mib 1`; **B**: also **`--keys-dir …\keys`**).
4. Kill sender (**Ctrl+C**) after **partial** `Sending:` output.
5. **`Test-Path` / `test ! -f`** on **`…/failsafe_demo_512m.bin`** inside the demo output dir must prove the **trusted final path never appeared** (`os.replace` not reached).
6. Peek **`*.part`** and **`.quarantine`** (`Get-ChildItem` / `ls`) — you may see only transient staging files, never a forged final basename until step 8 passes.
7. **Restart receiver + rerun sender from scratch** (defaults OK once you are past the deliberate interrupt).
8. Compare **streaming SHA‑256** (`common.hashing.sha256_hex_digest_file`) between source **`failsafe_demo_512m.bin`** and the received path.

---

## Approach A

### Wrong CA / wrong trust anchor (TLS handshake or chain verification fails)

The sender must trust the same CA that signed the server certificate. Point `--ca-cert` at a **non-CA** PEM (for example the server leaf cert) so chain building fails.

**Receiver (terminal 1)**

```powershell
python approach-a-mtls\receiver.py --host 127.0.0.1 --port 8443 --output-dir received
```

**Sender (terminal 2)** — note the wrong `--ca-cert`:

```powershell
python approach-a-mtls\sender.py --host 127.0.0.1 --port 8443 --file testing_1mb.bin `
  --ca-cert approach-a-mtls\certs\server-cert.pem
```

Expect a TLS / certificate verification error and **no** completed upload.

### SHA-256 mismatch after full payload (receiver fail-closed)

The receiver accepts metadata first, then streams plaintext into `*.part`, then compares **streaming SHA-256** to `sha256_hex` before `os.replace`.

**Receiver**

```powershell
python approach-a-mtls\receiver.py --host 127.0.0.1 --port 8443 --output-dir received
```

**Malicious client script** (valid mTLS, wrong declared digest):

```powershell
python scripts\a_tls_send_wrong_metadata_sha.py --host 127.0.0.1 --port 8443 --file testing_1mb.bin --remote-name testing_1mb.bin
```

Expect receiver stderr such as `SHA-256 mismatch` and **`received\testing_1mb.bin` must not appear** (only the `.part` may exist briefly before quarantine/delete).

### Mid-transfer abort: no final file

Use **two terminals** (receiver blocks on `accept`). Create `testing_1mb.bin` (see above). Use a **small** chunk size so the payload loop runs long enough to interrupt.

**Receiver (terminal 1)**

```powershell
python approach-a-mtls\receiver.py --host 127.0.0.1 --port 8443 --output-dir received
```

**Sender (terminal 2)** — press **Ctrl+C** during the **`Sending:`** phase (after the TLS handshake). With a **1 MiB** file the default progress interval often yields **only a final** `Sending:` line at **100%**—interrupt as soon as that line appears, or use **`README.md` → Fail-safe demo** (512 MiB + `--progress-interval-mib 1`) for clearer partial progress.

```powershell
python approach-a-mtls\sender.py --host 127.0.0.1 --port 8443 --file testing_1mb.bin --remote-name demo-abort.bin --chunk-size 65536
```

**Check**

```powershell
Test-Path .\received\demo-abort.bin
Test-Path .\received\demo-abort.bin.part
```

Expect **`False`** for `Test-Path .\received\demo-abort.bin` (no promoted final file). A `*.part` may appear briefly or be deleted on abort; **`.quarantine\`** is used mainly when `_fail()` runs after a full ingest with a digest/size mismatch—not typical for a mid‑drop.

---

## Approach B

### Wrong signing / identity material (handshake or manifest verification fails)

Generate a **second** key set in a separate directory, then make the receiver trust the **wrong** sender Ed25519 public key (everything else copied from the good set so X25519 material still matches for a moment — actually for a clean demo, replace only `sender_ed25519_public.pem` on the receiver side with a key from `keys-alt` so **Ed25519 verify** fails while long-term X25519 files are unchanged).

**One-time setup**

```powershell
python approach-b-envelope\generate_keys.py --output-dir approach-b-envelope\keys-alt --force
New-Item -ItemType Directory -Force approach-b-envelope\keys-wrong-demo | Out-Null
Copy-Item approach-b-envelope\keys\*.pem approach-b-envelope\keys-wrong-demo\
Copy-Item approach-b-envelope\keys-alt\sender_ed25519_public.pem approach-b-envelope\keys-wrong-demo\sender_ed25519_public.pem -Force
```

**Receiver** — uses tampered key dir:

```powershell
python approach-b-envelope\receiver.py --host 127.0.0.1 --port 9443 --keys-dir approach-b-envelope\keys-wrong-demo --output-dir received-b
```

**Sender** — still uses the **good** keys:

```powershell
python approach-b-envelope\sender.py --host 127.0.0.1 --port 9443 --keys-dir approach-b-envelope\keys --file testing_1mb.bin --remote-name testing_1mb.bin
```

Expect `invalid sender handshake signature` (or similar) and **no** `received-b\testing_1mb.bin`.

`keys-alt` and `keys-wrong-demo` are ignored by `.gitignore` (see repo root `.gitignore`).

### Tamper MANIFEST JSON, MANIFEST signature, or ciphertext in flight (relay)

Terminal layout:

| Role | Port | Command |
|------|------|-----------|
| Real receiver | 9443 | `python approach-b-envelope\receiver.py ... --port 9443` |
| Relay (mutates bytes) | 9444 | `python scripts\b_tcp_relay_tamper.py --listen-port 9444 --upstream-port 9443 --mode …` |
| Sender | →9444 | `python approach-b-envelope\sender.py --host 127.0.0.1 --port 9444 ...` |

**1) Receiver on 9443**

```powershell
python approach-b-envelope\receiver.py --host 127.0.0.1 --port 9443 --keys-dir approach-b-envelope\keys --output-dir received-b
```

**2) Relay** (pick one `--mode`):

```powershell
python scripts\b_tcp_relay_tamper.py --listen-port 9444 --upstream-port 9443 --mode manifest-json
```

```powershell
python scripts\b_tcp_relay_tamper.py --listen-port 9444 --upstream-port 9443 --mode manifest-sig-byte
```

```powershell
python scripts\b_tcp_relay_tamper.py --listen-port 9444 --upstream-port 9443 --mode first-chunk-byte
```

**3) Sender → relay (note port 9444)**

```powershell
python approach-b-envelope\sender.py --host 127.0.0.1 --port 9444 --keys-dir approach-b-envelope\keys --file testing_1mb.bin --remote-name testing_1mb.bin
```

Expect:

- `manifest-json` / `manifest-sig-byte` → invalid manifest signature or parse error before payload commit.
- `first-chunk-byte` → AEAD tag verification failure on the first chunk.

### SHA-256 mismatch on Approach B

The stock sender always hashes before signing, so it will not produce a mismatched manifest by itself. For a **manifest hash lie** demo you can:

- Use the **relay** `manifest-json` mode which changes a digit in the JSON so the signature no longer matches (receiver rejects before writing plaintext), or
- Temporarily fork the sender for a course demo (not shipped here).

To show **receiver streaming hash vs file** mismatch without a relay, use **ciphertext tamper** (`first-chunk-byte`): plaintext written would not match declared digest if decryption succeeded — but decryption fails first, which is the intended fail-closed behaviour.

### Mid-transfer abort: no final output file

Use **two terminals**. Use a 1 MiB file and a **small** `--chunk-plaintext-max` so the encrypted payload loop runs long enough to interrupt.

**Receiver (terminal 1)**

```powershell
python approach-b-envelope\receiver.py --host 127.0.0.1 --port 9443 --keys-dir approach-b-envelope\keys --output-dir received-b
```

**Sender (terminal 2)** — press **Ctrl+C** during **`Sending:`** (same caveat as Approach A for **1 MiB** + default progress—see **`README.md` → Fail-safe demo** for a clearer 512 MiB recording path).

```powershell
python approach-b-envelope\sender.py --host 127.0.0.1 --port 9443 --keys-dir approach-b-envelope\keys --file testing_1mb.bin --remote-name demo-b-abort.bin --chunk-plaintext-max 65536
```

**Check**

```powershell
Test-Path .\received-b\demo-b-abort.bin
```

Expect **`False`**. The receiver deletes the `.part` file when the chunk loop aborts; you should not see a promoted final file.

**Path consistency:** these **1 MiB** snippets use **`received\`** / **`received-b\`** and **`demo-abort*.bin`**. The **canonical** 512 MiB recording walkthrough uses **`received-failsafe-demo\`**, **`received-b-failsafe-demo\`**, and **`failsafe_demo_512m.bin`** — see **`README.md` → Fail-safe demo**.

---

## Optional automated smoke test (stdlib `unittest`, no pytest required)

Full suite (including fail‑closed security negatives):

```powershell
python -m unittest discover -s tests -v
```

**Unix**

```bash
python3 -m unittest discover -s tests -v
```

Single-module smoke (`make_test_file` only):

```powershell
python -m unittest tests.test_make_test_file_script -v
```

```bash
python3 -m unittest tests.test_make_test_file_script -v
```

---

## Stretch evidence (throughput & rubric §4.2)

For **4 GiB** grading / demo capture, follow **`README.md` → §4 GiB evidence checklist** (especially **Throughput measurement** and the **results table**). That section also documents **sparse `zero4g.bin`**, **pick‑one** creation paths, and the **`--- 4 GiB evidence semantics ---`** block written into **`evidence/transfer_evidence_*.txt`** by **`run_4gb_evidence.py`** / **`collect_evidence.py`**.

**What to paste or screenshot**

- After each successful **Approach A** run: sender line **`Send throughput:`** and receiver line **`Throughput:`** (both include **MB/s (SI)** and **MiB/s**).
- After each **Approach B** run: sender and receiver lines **`Payload throughput:`** (same two units).
- Do **not** use the earlier **`Hashing:`** / **`SHA‑256 (streaming): … [… MB/s]`** lines as “transfer throughput” — those time the **pre‑flight hash** on disk.

**Forward secrecy / non‑goals**

- Narrative for reviewers: **`DESIGN.md` §2.4** (ephemeral X25519 for B, TLS ECDHE preference + RSA‑kex caveat for A; **no** resumability; **no** broker).

---

## Frame index reference (Approach B relay)

Frames on the **sender → receiver** TCP byte stream (length-prefixed), zero-based index as implemented in `scripts/b_tcp_relay_tamper.py`:

| Index | Typical content |
|------|-----------------|
| 0 | `HELLO1` JSON |
| 1 | `HANDSHAKE_SIG_S` (64 bytes) |
| 2 | `MANIFEST` JSON |
| 3 | `MANIFEST_SIG` (64 bytes) |
| 4+ | Encrypted chunk binary frames |
