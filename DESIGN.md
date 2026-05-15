# Design: secure large-file transfer (CMPE272)

This document specifies the security model and **on-the-wire protocols** for both approaches. **Approach A** uses mutual TLS; **Approach B** uses **plain TCP** with **application-layer** authenticated encryption and signatures—intentionally different trust boundaries and failure modes.

---

## 1. Goals and non-goals

### Goals

- Stream multi-gigabyte files with **bounded memory** (one chunk in RAM at a time for application data paths).
- **Confidentiality** and **integrity** on a hostile network.
- **Mutual authentication** of sender and receiver (mechanism differs per approach).
- **Fail closed** on disk: final filename appears only after **SHA-256** over the full plaintext matches the declared digest.

### Non-goals

- Mid-transfer resume / partial restart protocols.
- Multi-client load balancing or long-lived receiver serving infinite sessions (receiver may accept one session per invocation unless extended later).

### Availability: assignment wording (fail-safe vs resumability)

The brief’s functional requirement **4.1 §8** states:

> **Each implementation must be resumable or, at minimum, fail-safe:** if the connection drops mid-transfer, **the receiver must not silently keep a partial file as if it were complete**.

**This submission implements the fail-safe minimum only.** If the TCP session ends early, receivers **abort loudly** and **never** rename `*.part` to the final output path unless streaming **SHA-256** plus byte-count checks succeed. Operators **restart the receiver**, then **restart the sender**, so delivery begins again from the start of the file — **without** negotiated resume, signed offsets, or partial restart state.

Stretch item **§4.2** (“resumable transfer using signed chunk offsets …”) therefore remains intentionally **not implemented** alongside the bullet non‑goals above.

---

## 2. Threat model

This section summarizes how each **assignment implementation** treats common threats. The tables describe **this repository’s code paths** and documented limits; they are not a formal security proof.

### 2.1 Approach A (mTLS) — threat responses

| Threat | How the design responds | Limits / residual risk |
|--------|-------------------------|-------------------------|
| **Passive eavesdropper** | TLS 1.2 **record encryption** hides plaintext file bytes and metadata payloads on the wire. | Record sizes and timing still leak coarse information (traffic analysis). |
| **Active MITM modifies bytes** | TLS **authenticates** records; MAC verification failure aborts the connection. Chains bind identities to the configured **local CA**. | Wrong `--ca-cert`, compromised CA, or added enterprise inspection roots break the trust model. |
| **Spoofed sender or receiver** | **Mutual TLS**: server and client each present a certificate; `ssl` verifies chains and (for the client) hostname/SAN against `localhost` for loopback. | **TOFU**: replacing `approach-a-mtls/certs/*.pem` on disk with attacker-controlled material defeats both peers. |
| **Replay of an earlier transfer** | Each connection runs a **new TLS handshake** with fresh keys. The application does not tag sessions; the receiver always checks **streaming SHA-256** vs metadata for the bytes received in that connection. | Replaying ciphertext **inside a new TLS session** still delivers bytes; whether that is a policy violation is **application-defined** (not distinguished here). |
| **Connection drops at ~80%** | Receiver writes only `received/<name>.part`; on truncation or error it **does not** `os.replace` to the final name; partial data is deleted or quarantined. | A `.part` file may exist briefly until cleanup. |
| **Untrusted intermediary (router, hotspot, TLS-inspecting proxy)** | With the **dev CA** trusted only by sender and receiver, the intermediary sees **TLS ciphertext** only. | If a proxy performs TLS interception with a **different** trust root not configured here, verification **fails closed** (expected). |

### 2.2 Approach B (envelope) — threat responses

| Threat | How the design responds | Limits / residual risk |
|--------|-------------------------|-------------------------|
| **Passive eavesdropper** | **Per-chunk AEAD** hides file plaintext. | **HELLO** / **MANIFEST** JSON (ephemeral X25519 pubs, `session_id`, filename, sizes) is sent in **cleartext** on TCP. |
| **Active MITM modifies bytes** | **Ed25519** over `handshake_transcript` and canonical manifest bytes; **AEAD tags** on each chunk. Any tampering should fail verification before a trusted final file exists. | A fork that skips signature verify is trivially vulnerable (§9). |
| **Spoofed sender or receiver** | Long-term **Ed25519** and **X25519** PEMs on disk; transcript and manifest signatures bind the session to those keys; ECDH combines static + ephemeral material per §5.4. | Ed25519 and X25519 keys are **separate PEM files**—they must be distributed **together** and verified out-of-band once (§9). |
| **Replay of an earlier transfer** | In-process **`session_id`** set for **completed** transfers; receiver enforces **strict increasing `chunk_index`** with AAD binding index and length. | **Receiver restart** clears the `session_id` cache; full stream replay to a fresh process is discussed in §9. |
| **Connection drops at ~80%** | Same fail-closed pattern as A: write to `*.part` only; delete/quarantine on error; no final rename until size and SHA-256 match. | Same. |
| **Untrusted intermediary** | **Plain TCP** — every framing byte is visible. Security is entirely from **signatures + AEAD + HKDF**, not link encryption. | Strong metadata leakage (filenames, sizes); no padding in v1. |

### 2.3 Comparative summary

| Concern | Approach A | Approach B |
|---------|------------|------------|
| **Link secrecy** | Strong (TLS records) | None at transport |
| **Peer authentication** | X.509 (mTLS) | Ed25519 + signed manifest / transcript |
| **Primary implementation API** | `ssl` + framing | `cryptography` + framing |

### 2.4 CIAA mapping (assignment rubric)

The course brief maps **CIAA** to concrete mechanisms. Here **C** = **Confidentiality**, **I** = **Integrity**, the first **A** = **Authenticity** (mutual identification / binding), and the second **A** = **Availability** as in the assignment wording (**fail-safe** vs resumable). If your brief uses **“accountability”** language, treat it alongside **Authenticity** here: **mTLS** and **Ed25519** transcripts/manifests tie actions to named peers.

Below, each property names the **implementation artifact** that satisfies it. **Availability** matches **§1** (*Availability: assignment wording*): graders asked for **`"resumable or, at minimum, fail-safe"`** — **this codebase chooses fail-safe**, not resume-from-offset.

#### Approach A (mTLS)

| CIAA | Property | Mechanism in this repo |
|------|----------|------------------------|
| **C** | Confidentiality | TLS 1.2 **record encryption** protects metadata JSON and all file bytes on the wire (`ssl`); file bytes never sent as raw TCP payload. |
| **I** | Integrity | TLS **record MAC** detects in-flight tampering; receiver computes **streaming SHA-256** over decrypted plaintext and compares to `sha256_hex` before rename. |
| **A** | Authenticity | **Mutual TLS**: client + server certificates verified against the same **local CA** PEM (`--ca-cert`); `VERIFY_FAIL_IF_NO_PEER_CERT`. |
| **A** | Availability | **TCP** retransmission and blocking reads/writes; **chunked** sender/receiver loops; on drop or error the receiver **does not** promote `*.part` to the final name (delete/quarantine). **Restart** = full re-transfer (acceptable fail-safe per §4.1 #8). |

#### Approach B (envelope)

| CIAA | Property | Mechanism in this repo |
|------|----------|------------------------|
| **C** | Confidentiality | **ChaCha20-Poly1305** or **AES-256-GCM** per chunk (`cryptography`); **32-byte `file_key`** from **HKDF-SHA256** over X25519-derived IKM (§5.4). **File plaintext** never appears on the wire; control JSON is cleartext (metadata leakage called out in §2.2). |
| **I** | Integrity | **AEAD tag** per chunk + **AAD** binds `session_id`, `chunk_index`, and plaintext length; **streaming SHA-256** over decrypted plaintext vs `plaintext_sha256_hex` in manifest before rename. |
| **A** | Authenticity | **Ed25519** over `handshake_transcript` (both peers) and over **canonical MANIFEST** (sender); `sender_identity` + `timestamp` bound into signed manifest. |
| **A** | Availability | Same as A: TCP + chunked streams; **fail-closed** disk path; no resumable offsets in v1. |

#### Stretch goals (rubric §4.2) — partial credit claimed

| Stretch item | Status |
|--------------|--------|
| Resumable signed chunk offsets | **Not implemented** — assignment **fail‑safe** minimum is used instead (**`DESIGN.md` §1**); interrupted transfers require a **full re-transfer** (no negotiated resume offsets in v1). |
| Throughput measurement | **Yes** — both stacks print **MB/s (SI)** and **MiB/s (1024²)** for the **payload** phase; see **§2.4.1**. |
| Forward secrecy | **Approach B:** ephemeral X25519 per session in the handshake (**§5.4**); **Approach A:** TLS key schedule when an **ECDHE** AEAD suite negotiates (**§2.4.2**, **`common.constants.TLS12_MT_ALLOWED_CIPHER_LIST`**). |
| Untrusted broker / object store | **Not used** — direct sender→receiver TCP only; broker/object‑store threat model is **out of scope**. |
| Rate-limited retry / backoff | **Not implemented** — single attempt per process invocation; operators restart manually. |

##### §2.4.1 Throughput reporting (where to read numbers)

Throughput lines are **stdout** on the sender and receiver after a **successful** payload transfer (distinct from the earlier **hashing** pass, which also prints MB/s for the first disk read).

| Stack | Role | Log prefix |
|-------|------|------------|
| **Approach A** | Sender | **`Send throughput:`** |
| **Approach A** | Receiver | **`Throughput:`** |
| **Approach B** | Sender | **`Payload throughput:`** |
| **Approach B** | Receiver | **`Payload throughput:`** |

Each line includes **`MB/s (SI)`** and **`MiB/s (1024^2)`** in one string. For grading evidence, capture **one line per role per 4 GiB run** (four numbers total across both approaches). See **`README.md` §4 GiB evidence checklist** for a copy‑paste table template.

##### §2.4.2 Forward secrecy — Approach B (envelope)

- **Ephemeral X25519:** sender and receiver each generate a fresh ephemeral X25519 key pair every session; public bytes appear in **HELLO1** / **HELLO2** (**§5.5**). They are folded with **long‑term static X25519** keys into \(K_1, K_2\) and then **`file_key`** via HKDF (**§5.4**).
- **Ed25519 vs file confidentiality:** long‑term **Ed25519** keys sign the handshake transcript and the manifest; they **do not** participate in the X25519/HKDF derivation of **`file_key`**. Therefore **compromise of Ed25519 signing keys alone** does **not**, by itself, let an attacker decrypt **past file ciphertext** (it may let them forge future manifests if key distribution is not repaired—an **authenticity** concern, not bulk decryption of old payloads from those keys alone).
- **Limits:** **`file_key`** and ephemeral scalars live in **process memory** for the session; this codebase does **not** write them to disk. **Operational risks** remain (swap, crash dumps, invasive malware, accidental debug logging). **Compromise of long‑term X25519 private keys** together with a **recorded wire transcript** of that session can allow a passive attacker to re‑derive **`file_key`** for that session (standard DH replay). Destroying ephemeral secrets after the session ends limits **future** compromise windows in the usual “FS vs long‑term key compromise” model.

##### §2.4.3 Forward secrecy — Approach A (mTLS)

- **TLS 1.2 + AEAD only:** `TLS12_MT_ALLOWED_CIPHER_LIST` in **`common.constants`** restricts the client and server to **AES‑GCM** / **ChaCha20‑Poly1305** record ciphers; **ECDHE‑RSA** variants are listed **first** so OpenSSL/Windows stacks **prefer ephemeral Diffie–Hellman** key agreement where available.
- **When FS applies:** if the negotiated cipher is an **ECDHE** suite, recorded ciphertext should remain hard to decrypt after ephemeral secrets are erased, even if the **RSA** certificate key is compromised later (standard TLS FS story).
- **RSA key‑exchange fallbacks:** the list intentionally includes **`RSA-AES256-GCM-SHA384`** / **`RSA-AES128-GCM-SHA256`** for stacks that lack ECDHE_RSA + AEAD; these suites still give **AEAD integrity/confidentiality on the wire** for the **current** session but **do not** provide **ECDHE‑grade forward secrecy** against a later compromise of the server’s RSA decryption key on recorded traffic. Operators who need strongest FS guarantees should verify the negotiated suite (e.g. temporary `ssl_sock.cipher()` logging in a lab probe) and adjust local OpenSSL build / cipher string if required—**outside** this repo’s default compatibility choice.

---

## 3. Shared building blocks

- **Chunked file I/O:** `common/streaming.py` — `iter_file_chunks`, etc.
- **Plaintext integrity:** `common/hashing.py` — streaming SHA-256 for the final file.
- **Atomic promotion:** `common/atomic_io.py` — write `*.part`, verify, then `os.replace`.
- **Framing:** `common/framing.py` — length-prefixed JSON and binary blobs over TCP (4-byte big-endian `uint32` length + payload).

---

## 4. Approach A — mutual TLS (one-page design)

### 4.1 ASCII architecture

```
                    +------------------+         TLS 1.2          +------------------+
  [ Sender ] -----> |  TCP + ssl.wrap  | <------------------------> |  TCP + ssl.wrap  | <----- [ Receiver ]
   client cert      |  ciphertext +    |   mutual auth (X.509)     |  server cert     |
   + CA trust       |  MAC on records  |                            |  + CA trust       |
                    +------------------+                            +------------------+
                              |                                              |
                              v                                              v
                     JSON: {filename, size, sha256_hex}          write received/<name>.part
                     then binary chunks (plaintext)               streaming SHA-256 vs sha256_hex
                                                                   os.replace -> final path
```

### 4.2 Protocol (application layer after TLS)

1. **Metadata:** one length-prefixed **JSON** frame: `filename` (single path component), `size` (bytes), `sha256_hex` (64 hex chars).
2. **Payload:** length-prefixed **binary** frames; payloads concatenate to exactly `size` bytes (plaintext inside the TLS tunnel).

### 4.3 Algorithms and parameters

| Mechanism | Choice in this repo |
|-----------|---------------------|
| TLS version | **1.2 only** (`minimum_version` / `maximum_version`) for predictable behaviour across Windows and OpenSSL stacks. |
| Record encryption | **AEAD suites only**: client and server set `SSLContext.set_ciphers()` to ECDHE‑RSA + **AES‑GCM** / **ChaCha20‑Poly1305**, plus RSA‑key‑exchange AEAD fallbacks (`common.constants.TLS12_MT_ALLOWED_CIPHER_LIST`). **No** CBC+HMAC negotiation (matches rubric “AEAD everywhere”). **ECDHE vs RSA kex:** see **§2.4.3** for forward‑secrecy implications. |
| Authentication | **Mutual** TLS: `CERT_REQUIRED`, client cert required, chain verification against the same **local CA** PEM. |
| File integrity | **SHA-256** (`hashlib` via `StreamingSha256`) computed incrementally on the receiver over decrypted plaintext. |
| Chunk size | Sender/receiver use `common.iter_file_chunks` with configurable `--chunk-size` (default `DEFAULT_CHUNK_SIZE_BYTES` = 1 MiB). Each chunk must satisfy `MAX_BINARY_PAYLOAD_BYTES` after framing. |
| Disk commit | `open_part_file` → `fsync` → size check → digest check → `replace_with_final` (`os.replace`). |

### 4.4 Key and certificate management

- **`generate_certs.py`** creates a small **local CA** (`ca-cert.pem` / `ca-key.pem`), a **server** cert/key (`CN=localhost`, SAN loopback), and a **client** cert/key (`CN=mtls-client`).
- Sender and receiver both load **`ca-cert.pem`** as trust anchor; each loads its own **role key pair**.
- **Operational rule:** treat `approach-a-mtls/certs/` as **secrets in development**; never commit private keys (`.gitignore` lists `*.pem` there).

### 4.5 Chunk size (Approach A)

Chunk size controls how much plaintext is read from disk (sender) or written per `recv_binary_frame` (receiver) **per step**. Larger chunks reduce syscall/frame overhead; smaller chunks reduce peak memory and improve progress reporting granularity. The **wire limit** is `MAX_BINARY_PAYLOAD_BYTES` (see `common.constants`).

### 4.6 Implementation reference

Source of truth: `approach-a-mtls/receiver.py` and `approach-a-mtls/sender.py` module docstrings and argparse defaults.

---

## 5. Approach B — envelope over plain TCP (normative protocol)

**Transport:** cleartext **TCP** (no TLS). All confidentiality and integrity for file bytes come from **AEAD**; endpoint authentication comes from **Ed25519** and **X25519** using **`cryptography`** (no custom ciphers).

### 5.0 One-page architecture (overview)

```
 [Sender]                                    [Plain TCP wire]                         [Receiver]
     |  HELLO1 (JSON)  ----------------->    cleartext framing                         recv HELLO1
     |  <------------------  HELLO2 (JSON)                                           send HELLO2
     |  HANDSHAKE_SIG_S (bin) --------->                                           verify Ed25519
     |  <------------------ HANDSHAKE_SIG_R (bin)                                    sign + send
     |  MANIFEST + MANIFEST_SIG ------->                                           verify manifest sig
     |  AEAD chunk frames ------------->                                           decrypt -> .part
     |                                                                               SHA-256; replace
```

**Algorithms:** **Ed25519** signatures on `handshake_transcript` (§5.5.3) and on canonical **MANIFEST** bytes (§5.6); **X25519** ECDH for \(K_1, K_2\) (§5.4); **HKDF-SHA256** → 32-byte **`file_key`**; **ChaCha20-Poly1305** (preferred) or **AES-256-GCM** per chunk; **SHA-256** over decrypted plaintext for final verification.

**Chunk size:** `chunk_plaintext_max` in **HELLO1** (sender-chosen within framing limits). Plaintext reads are ≤ this value; the last chunk may be shorter. Ciphertext frame size includes a small header + AEAD expansion (16-byte tag). Hard cap: `MAX_BINARY_PAYLOAD_BYTES`.

**Key management:** Long-term **Ed25519** + **X25519** PEMs from `generate_keys.py`; **ephemeral X25519** generated per session in RAM only. **`session_id`**: 16 random bytes as 32 hex chars; replay policy §5.3.

The following subsections (§5.1 onward) are the **normative** wire format and crypto details.

### 5.1 Design principles (difference from mTLS)

| Aspect | mTLS (A) | Envelope (B) |
|--------|----------|----------------|
| Transport security | TLS record layer | None at transport |
| File confidentiality | Inside TLS tunnel | Per-chunk AEAD at application layer |
| Peer identity | X.509 chain | Ed25519 verify + signed manifest / transcript |
| Key establishment | TLS handshake | X25519 ECDH + HKDF (this spec) |

### 5.2 Long-term vs ephemeral keys

**Long-term** (generated by `approach-b-envelope/generate_keys.py`, distributed out-of-band / on disk next to binaries):

| Key | Owner | Purpose |
|-----|--------|---------|
| Ed25519 secret / public | Sender | Sign handshake transcript and **manifest** |
| Ed25519 secret / public | Receiver | Sign handshake transcript (receiver proof) |
| X25519 static secret / public | Sender | ECDH input for session key material |
| X25519 static secret / public | Receiver | ECDH input for session key material |

**Ephemeral (per TCP session / transfer):**

| Key | Owner | Purpose |
|-----|--------|---------|
| X25519 ephemeral key pair | Sender | Fresh ECDH contribution each session |
| X25519 ephemeral key pair | Receiver | Fresh ECDH contribution each session |

Ephemeral private keys **must only exist in memory** for the session; they are **never** written to PEM for this protocol.

### 5.3 Session identifier and replay posture

- **`session_id`:** 16 random bytes (128 bits), hex-encoded as 32-character string in JSON, generated by **sender** at the start of each transfer attempt.
- **Replay policy (receiver):**
  - Receiver maintains an in-memory set (or single “last seen”) of `session_id` values it has **fully accepted** (manifest verified and at least one chunk accepted) for the lifetime of the process **or** rejects any duplicate `session_id` presented after a successful completion for that id.
  - Minimum bar: **reject a second connection** that presents the same `session_id` as a completed transfer while the receiver process still holds state; document that restarts clear replay cache (operational limitation).
- **In-order chunks:** Receiver accepts ciphertext chunks **only** for strictly increasing `chunk_index` starting at `0`. Any gap, duplicate index, or index ≥ `chunk_count` from the manifest → **fail closed** (see §5.9). This stops chunk-level replay within a session.

### 5.4 Key agreement — shared secrets and file key

Let:

- \(e_s\) = sender ephemeral X25519 key pair; \(E_s\) = public  
- \(e_r\) = receiver ephemeral X25519 key pair; \(E_r\) = public  
- \(S\) = sender static X25519 key pair; \(S_p\) = sender static public  
- \(R\) = receiver static X25519 key pair; \(R_p\) = receiver static public  

Both peers know all four public keys after the hello exchange. Define:

1. \(K_1 = \mathrm{X25519}(e_s^{priv}, R_p) = \mathrm{X25519}(R^{priv}, E_s)\)  
2. \(K_2 = \mathrm{X25519}(S^{priv}, E_r) = \mathrm{X25519}(e_r^{priv}, S_p)\)

**Sender** computes \(K_1\) with \(e_s^{priv}\) and receiver’s long-term \(R_p\) (from file). Computes \(K_2\) with sender static \(S^{priv}\) and \(E_r\) from HELLO2.

**Receiver** computes \(K_1\) with \(R^{priv}\) and \(E_s\) from HELLO1. Computes \(K_2\) with \(e_r^{priv}\) and \(S_p\) from file.

Concatenate **IKM** \(= K_1 \,\|\, K_2\) (each 32 bytes, fixed order).

**KDF:**

- **Extract:** `PRK = HKDF-Extract(salt = SHA256("cmpe272-b-session-v1" || session_id_raw_bytes), ikm = IKM)`  
  - `session_id_raw_bytes` = 16 bytes from hex decode of `session_id`.
- **Expand:** `file_key = HKDF-Expand(PRK, info = b"cmpe272-approach-b/file-aead-key/v1", L = 32)`  

Use **`cryptography.hazmat.primitives.kdf.hkdf.HKDF`** (SHA-256) with the above `salt` and `info`. The resulting **32-byte** `file_key` is the symmetric key for **ChaCha20-Poly1305** (preferred) or **AES-256-GCM** if explicitly chosen in code; the design treats them equivalently at the AEAD level (128-bit tag, distinct nonce rules below).

*Rationale:* \(K_1\) binds the session to **receiver static** (only real receiver derives same \(K_1\)); \(K_2\) binds to **sender static** (only real sender derives same \(K_2\)). Ephemerals provide **forward secrecy** for past sessions against static key compromise **only** if the compromise does not include ephemeral secrets (standard caveat).

### 5.5 Handshake messages (order)

All messages use **`common/framing`**: length-prefixed JSON objects **or** length-prefixed raw binary, as indicated. UTF-8 for JSON.

| Step | Direction | Message type | Payload |
|------|-----------|--------------|---------|
| H1 | S → R | `HELLO1` (JSON) | See §5.5.1 |
| H2 | R → S | `HELLO2` (JSON) | See §5.5.2 |
| H3 | S → R | `HANDSHAKE_SIG_S` (binary) | 64-byte **raw** Ed25519 signature |
| H4 | R → S | `HANDSHAKE_SIG_R` (binary) | 64-byte **raw** Ed25519 signature |
| M1 | S → R | `MANIFEST` (JSON) | See §5.6 (unsigned body) |
| M2 | S → R | `MANIFEST_SIG` (binary) | 64-byte raw Ed25519 signature over manifest canonical bytes |
| D* | S → R | `CHUNK` (binary) | See §5.7 |

Until H4 completes, neither side may send file data. Receiver must verify H3 before sending H2 is “committed” from its side—actually order is H1, H2, H3, H4: sender signs transcript that includes receiver ephemeral; receiver signs transcript that includes both ephemerals. After H4, sender sends manifest.

#### 5.5.1 `HELLO1` JSON fields

| Field | Type | Description |
|-------|------|-------------|
| `msg_type` | string | literal `"HELLO1"` |
| `protocol_version` | int | `1` |
| `session_id` | string | 32 hex chars (16 bytes) |
| `sender_ephemeral_x25519_pub` | string | base64url **raw** 32-byte public key |
| `chunk_plaintext_max` | int | max plaintext per chunk (e.g. `1048576`) |

#### 5.5.2 `HELLO2` JSON fields

| Field | Type | Description |
|-------|------|-------------|
| `msg_type` | string | literal `"HELLO2"` |
| `protocol_version` | int | echo `1` |
| `session_id` | string | **must equal** HELLO1 `session_id` |
| `receiver_ephemeral_x25519_pub` | string | base64url raw 32-byte public key |

#### 5.5.3 Transcript for handshake signatures

Define **`handshake_transcript`** as the strict concatenation of UTF-8 bytes:

```text
"CMPE272-B-HANDSHAKE-v1" || LF ||
hex(session_id) || LF ||
base64url(sender_ephemeral_x25519_pub) || LF ||
base64url(receiver_ephemeral_x25519_pub) || LF ||
decimal(protocol_version) || LF ||
decimal(chunk_plaintext_max)
```

- **`HANDSHAKE_SIG_S`:** Ed25519 signature by **sender** long-term signing key over `handshake_transcript`.  
- **`HANDSHAKE_SIG_R`:** Ed25519 signature by **receiver** long-term signing key over the **same** `handshake_transcript`.

Each peer verifies the other’s signature using the peer’s **Ed25519 public key** loaded from `approach-b-envelope/keys/` before any manifest or chunk processing.

### 5.6 Manifest fields and canonical signing input

**`MANIFEST` JSON** (no embedded signature; signature is separate frame):

| Field | Type | Description |
|-------|------|-------------|
| `msg_type` | string | `"MANIFEST"` |
| `protocol_version` | int | `1` |
| `session_id` | string | same as handshake |
| `filename` | string | single path segment (no `/` or `\`) |
| `size_bytes` | int | total plaintext size ≥ 0 |
| `chunk_count` | int | number of chunks \(N = \lceil \texttt{size\_bytes} / \texttt{chunk\_plaintext\_max} \rceil\) |
| `chunk_plaintext_max` | int | must match handshake |
| `plaintext_sha256_hex` | string | lowercase hex SHA-256 of entire plaintext |
| `aead` | string | `"chacha20-poly1305"` or `"aes-256-gcm"` (implementation fixed or negotiated here only as literal) |
| `sender_identity` | string | lowercase hex SHA-256 of the **raw** 32-byte sender Ed25519 public key (binds manifest to long-term sender identity) |
| `timestamp` | int | Unix time in seconds when the manifest was created; receiver SHOULD reject manifests outside a small skew window (e.g. ±10 minutes) |

**Canonical manifest bytes** for signing (UTF-8):

- Take the manifest **JSON object including `msg_type`**, serialize with **sorted keys**, minified:  
  `json.dumps(manifest_dict, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode("utf-8")`  
- The signature is over **exactly** those bytes (no trailing newline).

**`MANIFEST_SIG`:** Ed25519 signature by **sender** long-term key over the **canonical manifest bytes**.

**Receiver actions:** Verify Ed25519 manifest signature **before** decrypting chunks. Validate `chunk_count` vs `size_bytes` and `chunk_plaintext_max`. Reject oversized `size_bytes` vs CLI `--max-bytes`.

### 5.7 Chunk envelope: nonce, AAD, ciphertext

**Plaintext chunk** \(P_i\): up to `chunk_plaintext_max` bytes; last chunk may be shorter; sum of plaintext lengths = `size_bytes`.

**Chunk index:** \(i \in [0, N-1]\), four-byte big-endian `uint32` on the wire for the chunk header (or inside AAD only—implementation must match receiver parser).

**Nonce (12 bytes for ChaCha20-Poly1305; 12-byte IV for AES-GCM in this design):**

```
nonce_i = nonce_12( session_id_raw_16bytes, chunk_index_i )
```

Construction:

1. `h = SHA256( b"cmpe272-b-nonce-v1" || session_id_raw || struct.pack(">I", chunk_index) )`  
2. `nonce_i = h[0:12]`

Properties: unique per (`session_id`, `chunk_index`) with overwhelming probability; **never** reuse `(file_key, nonce_i)` across chunks or sessions.

**Associated data (AAD)** for AEAD encrypt/decrypt (must be identical on both sides):

```
AAD_i = UTF-8("CMPE272-B-CHUNK-v1") || 0x00 || session_id_raw || BE_uint32(chunk_index) || BE_uint32(chunk_plaintext_len)
```

Where `chunk_plaintext_len` is the length of \(P_i\) (≤ `chunk_plaintext_max`).

**Ciphertext wire format (one binary frame per chunk after manifest):**

```
BE_uint32(chunk_index) || BE_uint32(ciphertext_len) || AEAD_ciphertext_and_tag
```

`AEAD_ciphertext_and_tag` is the **cryptography** output for the chosen AEAD (ciphertext concatenated with 16-byte tag as returned by the library’s `encrypt` API).

**Receiver:** For each chunk in order: parse header → derive `nonce_i` → **`decrypt` / `open`** with `file_key`, `nonce_i`, `AAD_i` → **authentication failure aborts the whole transfer** (no plaintext write for that chunk). On success, write decrypted plaintext to the `.part` file and update running SHA-256.

**Sender:** Must not send chunk \(i+1\) until \(i\) is accepted locally (optional pipelining forbidden in v1 to keep receiver simple).

### 5.8 What is signed (summary)

| Artifact | Signer | Verifier |
|----------|--------|----------|
| `handshake_transcript` | Sender (H3), Receiver (H4) | Receiver, Sender |
| Canonical manifest bytes | Sender (M2) | Receiver |

Chunk integrity is **not** separately signed with Ed25519; it is carried by **AEAD** (authenticator tag).

### 5.9 Partial transfer failure (fail closed)

1. Receiver opens `open_part_file(final_path)` → writes only to `*.part`.  
2. **Per chunk:** AEAD decrypt must succeed **before** appending plaintext to `.part`.  
3. If any decrypt fails, TCP closes, receiver **deletes or quarantines** `.part` (same policy as Approach A: prefer quarantine under `output_dir/.quarantine/` with timestamp), **no** `os.replace`.  
4. If connection drops before `chunk_count` chunks received → treat as failure; same cleanup.  
5. After `chunk_count` chunks: verify `part` size == `size_bytes` and streaming SHA-256 == `plaintext_sha256_hex`; only then **`replace_with_final`**.

Sender: on any error, close socket; may delete local temp state; receiver still fails closed as above.

### 5.10 Algorithm IDs (implementation constants)

- **HKDF / hash:** SHA-256.  
- **AEAD:** `ChaCha20Poly1305` preferred; `AESGCM` acceptable if key is 32 bytes and nonce 12 bytes.  
- **Ed25519 / X25519:** `cryptography.hazmat.primitives.asymmetric`.

---

## 6. Secrets and configuration

- Private keys loaded only from **PEM paths** on the CLI (default paths under `approach-b-envelope/keys/`).  
- Optional encryption of PEM at generation time: `ENVELOPE_KEY_ENCRYPTION_PASSWORD` (see `generate_keys.py`).  
- No secrets in source code.

---

## 7. Testing strategy

- **Manual failure demos:** see repository **`TESTING.md`** and **`scripts/`** (wrong TLS CA, wrong Ed25519 material, TCP relay byte flips, SHA mismatch client, mid-transfer abort).
- **Automated smoke:** `python -m unittest tests.test_make_test_file_script -v` (exact-size file generator used by demos).
- **Integration (happy path):** all‑zero 4 GiB **`zero4g.bin`** at repo root (choose **one** of: sparse NTFS **`SetLength`**, first‑time **`dd`**, or **`scripts/make_test_file.py --pattern-byte 0`** — see **`README.md`**); Approach A/B with **`--remote-name zero4g.bin`**, then compare **`received/zero4g.bin`** and **`received-b/zero4g.bin`** vs source via **`common.hashing.sha256_hex_digest_file`**.

## 8. Open questions / implementation notes

- **Pipelining:** v1 is strictly sequential chunks (simpler receiver).  
- **Concurrent sessions:** out of scope; single accepted transfer per receiver invocation unless extended.

---

## 9. Security review before implementation (residual risks)

The protocol is **meaningfully different from mTLS** (plain TCP, app-layer crypto) but the following limitations and risks should be explicit **before** coding:

1. **No transport confidentiality for handshake JSON**  
   Ephemeral X25519 public keys and `session_id` are visible on the wire. **Security depends entirely** on Ed25519 signatures over `handshake_transcript` and the peers’ **correct long-term public keys** on disk. A user who disables signature verification in a fork regains a trivial MITM.

2. **Metadata leakage**  
   Filenames, sizes, and timing are visible on TCP (TLS would hide record lengths better). Padding is **not** specified in v1.

3. **Replay window**  
   In-process `session_id` deduplication does **not** survive receiver restart; a captured full ciphertext stream could in theory be replayed to a **fresh** receiver process if long-term keys unchanged. Mitigation for high-assurance deployments: nonce DB or TLS—but that is Approach A.

4. **Trust on first use (TOFU)**  
   If an attacker replaces `*_public.pem` files on disk, they win. Same class as replacing CA bundles for Approach A.

5. **Binding static X25519 to Ed25519 identity**  
   This design uses **separate** key pairs (`generate_keys.py`). Unless the implementation **cryptographically binds** Ed25519 identity to X25519 static keys (e.g. cross-signed certificate, or single seed-derived keys—**not** recommended without expert design), a compromised file layout could theoretically substitute one public key without the other. **Mitigation for course quality:** document that all `keys/*.pem` must be distributed together and verified out-of-band once; optional future: sign X25519 static pubkeys with Ed25519 at keygen.

6. **Integer / size limits**  
   Parser must reject absurd `size_bytes` / `chunk_count` before allocation to avoid DoS (align with `common` framing `MAX_*`).

7. **Side channels**  
   Not addressed (constant-time Ed25519 verify is library responsibility).

Overall: for a **course / dev** setting with correctly loaded keys and strict verify, the design provides **mutual authentication**, **confidentiality** of file bytes, **integrity** per chunk and end-to-end file hash, and **fail-closed** disk behavior. It is **not** a drop-in replacement for TLS on the open internet without addressing metadata, replay after restart, and TOFU policies.
