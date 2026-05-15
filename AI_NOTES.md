# AI / tooling disclosure (CMPE272 final)

The assignment brief names **Claude** as an example AI assistant; this submission used **Cursor** (Composer / embedded model) and similar tooling under the same **“AI-assisted; human must review crypto”** rules. The reflection below applies to that stack.

This file documents how **automated assistants** contributed to the repository, what the course author **reviewed by hand**, and an honest reflection on **strengths and weaknesses** of that collaboration.

---

## What the AI wrote (high level)

- **Scaffolding and structure:** early directory layout (`common/`, `approach-a-mtls/`, `approach-b-envelope/`), `requirements.txt`, and initial `README` / `DESIGN` headings.
- **Shared utilities:** `common/streaming.py`, `common/hashing.py`, `common/framing.py`, `common/tcp.py`, `common/temp_files.py`, `common/atomic_io.py`, and related constants/error types—implemented as small, composable modules.
- **Approach A:** `generate_certs.py`, `receiver.py`, and `sender.py` for **TLS 1.2 mutual TLS**, length-prefixed metadata + binary chunks, streaming SHA-256, and atomic rename after verification.
- **Approach B:** `generate_keys.py`; **`receiver.py`** and **`sender.py`** for plain TCP, Ed25519 transcript + manifest signatures, X25519 static + ephemeral ECDH, HKDF-derived `file_key`, ChaCha20-Poly1305 / AES-GCM chunks, strict chunk ordering, and the same fail-closed disk pattern as Approach A.
- **Documentation passes:** expanded `DESIGN.md` (normative Approach B protocol, threat notes), consolidated `README.md` for assignment submission, added **`TESTING.md`** and **`scripts/`** (relay tamper, wrong-SHA TLS client, 1 MiB file generator, **`run_4gb_evidence.py` / `collect_evidence.py`** with **`transfer_evidence_*.txt`** semantics), plus a **`unittest`** smoke test for the file generator.
- **Debugging / polish:** fixes such as catching `InvalidSignature` on the Approach B sender, initializing progress counters on the receiver, and aligning manifest fields (`sender_identity`, `timestamp`) between code and spec.

---

## What I reviewed (human)

- **Cryptographic direction:** confirmed Approach B matches the course intent: **no TLS on the wire**, **Ed25519** for authentication of transcript + manifest, **X25519 + HKDF** for session/file key material, **AEAD** for confidentiality and per-chunk integrity, **no custom ciphers**—only `cryptography` / stdlib primitives.
- **Fail-closed I/O:** verified both approaches write to **`*.part`**, verify **size + SHA-256** (and for B, **AEAD decrypt before write**), then call **`os.replace`** / `replace_with_final`; traced exception paths so partial files are deleted or quarantined on failure.
- **Wire format alignment:** checked that sender and receiver use the same **length-prefix framing**, **manifest canonical JSON**, **chunk header layout**, **nonce and AAD** construction, and **HKDF salt/info** strings as written in `DESIGN.md`.
- **Operational docs:** ran end-to-end flows on **Windows** (PowerShell, venv, sparse 4 GiB file via `FileStream.SetLength`), and skimmed Unix equivalents for `dd` / bash activation differences.
- **Failure demos:** read through `TESTING.md` and the relay script logic (frame indices for tampering) so classroom steps match the implementation.

---

## AI collaboration rubric (honest + human-led)

The assignment expects an **honest, specific** account of AI use, evidence that the **human directed** the work (not passive rubber-stamping), and **at least one concrete example** of catching or correcting assistant output.

- **Human-led scope:** Cryptographic goals, **fail-closed** disk semantics, and **Approach B** wire format (**`DESIGN.md` §5**) were set and reviewed by the course author; assistants accelerated drafting and refactors, but **verification order**, **threat-model tables**, and **security negatives** were checked against code before treating the repo as submission-ready (**What I reviewed (human)** above).
- **Concrete correction (docs):** Early AI-assisted **`README.md`** drafts used **placeholder paths** (`path\to\your\file.bin`), which **break copy-paste grading**; the author **caught this while testing commands** and replaced them with **`zero4g.bin`**, **`scripts/make_test_file.py`** outputs, **`TESTING.md`**, and literal receiver/sender fences — see **One thing the AI did poorly** below.
- **Concrete stance (crypto):** Shortcuts such as **skipping manifest signature verification** or **reusing nonces** “for debugging” were **refused** for production **`receiver.py`**; see **One insecure suggestion the AI could have made — and how I rejected it** below (patterns assistants often suggest, explicitly ruled out here).

---

## One insecure suggestion the AI could have made — and how I rejected it

A common shortcut models suggest is **“skip manifest signature verification in development”** or **use a static `session_id` / fixed nonce to simplify debugging.”** That would **destroy** Approach B’s security story: an attacker (or buggy peer) could alter filenames, sizes, or ciphertext without detection, or **reuse nonces** under the same key.

**Rejection:** the receiver **must** verify **Ed25519** over the handshake **before** trusting the peer, verify the **manifest signature** before decrypting any chunk, derive **nonces from `(session_id, chunk_index)`**, and **fail closed** on any verification error. Debugging convenience is handled with **`TESTING.md`** and small **`scripts/`** demos—not by weakening verify paths in production code.

---

## One thing the AI did well

**End-to-end consistency:** once `DESIGN.md` §5 was clarified, the model kept **sender, receiver, and design** aligned (field names, byte order, HKDF labels, manifest canonicalization, and chunk framing). That reduced subtle integration bugs that are easy to introduce when two TCP peers are written separately.

---

## One thing the AI did poorly

**Early documentation used non-literal placeholders** (e.g. `path\to\your\file.bin`) in “exact command” blocks, which **breaks copy-paste demos** for graders and students. Placeholders are fine in prose, but **assignment-quality** docs need either a **real example filename** or a **script-generated test file**. That gap was fixed later by adding **`b_approach_b_e2e_payload.bin`**, **`testing_1mb.bin`** via `scripts/make_test_file.py`, and a dedicated **`TESTING.md`**.

---

## Disclosure (submission text)

Parts of this repository—including module structure, initial helper implementations, Approach A/B transfer scripts, and large sections of documentation—were drafted or revised with **AI-assisted editing in Cursor**. Cryptographic choices, threat-model tables, and **every fail-closed code path** were **human-reviewed** against `DESIGN.md` and course requirements before treating the work as submission-ready.

---

## Pre-submission checklist

- [ ] No private keys, PEMs, or passwords committed (`.gitignore` covers generated material).
- [ ] Dependencies limited to reviewed libraries (`cryptography`; stdlib otherwise).
- [ ] Both approaches enforce **mutual authentication** as specified.
- [ ] Both approaches use **chunked streaming** and verify **SHA-256** of final plaintext.
- [ ] **Fail-closed** disk semantics verified on the OS you demo (Windows and/or Linux).
