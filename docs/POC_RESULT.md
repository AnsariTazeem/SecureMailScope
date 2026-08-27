# SecureMailScope — POC Result Record

**Record date:** 2026-08-27

**Status:** Environment/bootstrap PASS; T01 manual verification PASS (corrected attempt; earlier failed attempt preserved); E2/E3A analyzer-path checkpoint PASS for its authorized scope. T02–T08 and all binary gates remain UNTESTED.

**Overall recommendation:** GO — PS159 is selected/finalized for Team Apex. The selection-grade technical POC is CLOSED; the demonstrated result establishes technical viability for proceeding with production implementation. This is a GO/selection decision, not a claim that the complete product or the complete original POC matrix is GREEN. T02–T08 and formal gates G01–G11 remain UNTESTED; full product validation is NOT COMPLETE.

## 1. Verified environment/bootstrap milestone — PASS

The only milestone marked PASS is the environment/bootstrap and `securemailscope doctor` milestone.

Verified evidence (2026-08-25):

| Item | Result |
|---|---|
| `securemailscope doctor` implemented | Yes (Typer CLI; deterministic checks in `tooling.py`) |
| Unit tests | 10 passed in 0.84 seconds |
| Ruff lint | Passed |
| Ruff formatting check | Passed |
| `git diff --check` | Passed |
| Real doctor run verdict | `READY` |
| Prerequisite checks | 11/11 passed |
| JSON validation of doctor report | Returned true |
| Real doctor exit code | 0 (`EXIT_OK`) |

Note: "JSON validation returned true" refers to validating the doctor report output as part of this milestone. The analyzer's JSON report POC criterion remains UNTESTED (Section 2).

## 1b. T01 manual verification — PASS (corrected attempt, 2026-08-26)

Independent manual verifier against the controlled SMTP ECDHE PCAP: 23/23 comparisons passed; 0 failed.

An earlier T01 attempt failed. That attempt is preserved locally in evidence artifacts and archives and is not overwritten. This section records the corrected run only.

| Item | Result |
|---|---|
| T01 PCAP SHA-256 | `772d166b5e2b32516c76833357ff309af0d99d7bc962cf4c685279fc662ab086` |
| Packets captured | 28 |
| Received packets | 28 |
| Dropped packets | 0 |
| Capture runtime | Recorded (see evidence log) |
| Verifier runtime | 12.280 seconds |
| Comparisons total | 23 |
| Comparisons passed | 23 |
| Comparisons failed | 0 |
| SMTP port | 2525 |
| STARTTLS split reconstruction | Frames 9 and 11 |
| Negotiated TLS version | 1.2 (0x0303) |
| Negotiated cipher suite | ECDHE-RSA-AES128-GCM-SHA256 (0xC02F) |
| ECDHE group | secp256r1 (group 23) |
| Forward Secrecy | Derived from packet evidence |
| Observable certificates | 2 (leaf and root) |
| Certificate properties | Verified (subject/issuer/SAN/serial/validity/key/sig) |
| OpenSSL chain verification (capture time) | Passed |

Evidence categories covered by the 23 passing comparisons: artifact hash integrity, PCAP metadata (pcapng, packet count), dumpcap capture log (received 28, dropped 0), capture interval epoch/UTC match, single TCP stream, SMTP port 2525 identification from content, SMTP banner direction and content, EHLO and STARTTLS capability, STARTTLS split reconstruction across frames 9 and 11, STARTTLS ordering (last split frame < 220 reply < ClientHello), TLS handshake message order (CH → SH → Cert → SKE → SHD → CKE), negotiated TLS version 0x0303 (TLS 1.2), negotiated cipher 0xC02F (ECDHE-RSA-AES128-GCM-SHA256), server named curve secp256r1 (group 23), Forward Secrecy derived from packet evidence, wire leaf certificate fingerprint, wire root certificate fingerprint, wire certificate properties (subject/issuer/SAN/serial/validity/key/sig), OpenSSL chain verification at capture time, and connection lifecycle (SYN, SYN/ACK, FIN both directions, zero RST).

## 1c. E2/E3A analyzer-path checkpoint — PASS (2026-08-27)

E2/E3A PASS for its authorized scope, using the unchanged T01 PCAP as integration truth. Proven scope:

- Generic read-only PCAP/PCAPNG intake.
- Streamed SHA-256 and capture provenance (packet count, all-packet capture epochs, file size, capture format and tool versions).
- Typed analyzer errors.
- Safe shell-free external-tool execution; bounded timeout and output handling.
- TShark-native TCP follow-stream reassembly.
- Ordered repeated `tls.handshake.type` values preserved.
- Conservative content-based SMTP classification; ports used only as hints.
- Pre-TLS plaintext boundary enforced.
- Split STARTTLS reconstruction.
- Strict command < response < ClientHello ordering.
- Accepted-TLS, rejected, accepted-without-TLS, truncated and incomplete states.
- Positive-proof requirement for accepted-without-TLS.
- No raw frame-concatenation fallback for authoritative reconstruction.
- Frozen T01 analyzer facts match the independent T01 truth.

Validation facts (recorded truthfully, including one environmental flake): v3 full suite before the final boundary regression 201 passed; final session-state suite 24 passed; one later full-suite run 201 passed plus one environmental `tshark_observe` 20-second timeout (a tool/performance flake, not a functional assertion failure — an isolated T01 integration retry passed 2/2); Ruff check passed; Ruff formatting check passed; `git diff --check` passed; `securemailscope doctor` reached READY 11/11; PCAP SHA-256 remained unchanged (`772d166b5e2b32516c76833357ff309af0d99d7bc962cf4c685279fc662ab086`).

The `tshark_observe` timeout is recorded transparently as an environmental/tool-performance flake under host resource pressure, not as a functional assertion failure. No fully clean final full-suite run is claimed after the added regression.

## 2. POC criteria status

- Protocol identification from content on non-standard ports — SMTP: PASS (T01 manual verifier). IMAP/POP3: UNTESTED
- STARTTLS upgrade handling, including rejected/broken cases — SMTP upgrade: PASS (T01). Rejection/broken: UNTESTED
- TCP/email session reconstruction, including segmentation and truncation — T01 single-stream reconstruction: PASS. Multi-segment/truncation: UNTESTED
- TLS handshake reconstruction and ordering — PASS (T01, 23/23; STARTTLS split across frames 9/11; handshake message order verified)
- Negotiated TLS version, cipher, key establishment/group — PASS (T01: TLS 1.2, 0xC02F, secp256r1)
- Forward Secrecy determination — PASS (T01: ECDHE derived from packet evidence)
- X.509 extraction and capture-time validation — PASS (T01: leaf/root fingerprint, properties, OpenSSL chain verify)
- Honest TLS 1.3 certificate invisibility — UNTESTED
- Evidence-backed findings/recommendations and policy-risk scoring — UNTESTED
- ML anomaly scoring (IsolationForest, fixed seed, train/test separation) — UNTESTED
- Analyzer JSON report validation — UNTESTED
- HTML report generation and JSON/HTML parity — UNTESTED

Note: The E2/E3A analyzer-path checkpoint (Section 1c) demonstrated the SMTP-specific analyzer capabilities — content-based identification, TShark-native reassembly, split STARTTLS reconstruction (frames 9/11), strict ordering, and transition-state reconstruction (accepted-TLS, rejected, accepted-without-TLS, truncated, incomplete) — matching frozen truth on the unchanged T01 PCAP. The formal controlled matrix (T02–T08) and binary gates (G01–G11) remain UNTESTED, so the full product / complete matrix is not claimed GREEN.

## 3. Controlled matrix T01–T08

| Test | Status | Evidence |
|---|---|---|
| T01 SMTP ECDHE | PASS (corrected) | 23/23 passed, 0 failed; SHA-256 `772d166b5e2b32516c76833357ff309af0d99d7bc962cf4c685279fc662ab086`; 28 packets, received 28, dropped 0; port 2525; STARTTLS frames 9/11; TLS 1.2, 0xC02F, secp256r1; 2 certs; capture+verifier runtimes recorded; earlier attempt preserved |
| T02 IMAP STARTTLS | UNTESTED | — |
| T03 POP3 STLS | UNTESTED | — |
| T04 TLS 1.3 invisibility | UNTESTED | — |
| T05 STARTTLS rejection | UNTESTED | — |
| T06 Accepted without TLS | UNTESTED | — |
| T07 Truncated capture | UNTESTED | — |
| T08 ML anomaly | UNTESTED | — |

No controlled email PCAP fixtures for T02–T08 have been created or analyzed. T01 evidence is recorded in Section 1b. Any T02–T08 result not backed by independent verifier output is deliberately absent.

## 4. Binary gates G01–G11

G01 through G11 remain UNTESTED at the formal gate level. T01 evidence provides packet-level support for partial elements of several gates (e.g., G01 SMTP identification, G04 TLS ordering, G05 version/cipher extraction, G06 Forward Secrecy, G07 X.509 extraction), but full gate evaluation requires T02–T08 completion and analyzer-path validation. No gate is marked PASS or FAIL.

## 5. Outstanding verification steps

The selection-grade technical POC is CLOSED and does not depend on these for the GO/selection decision. Remaining production implementation/testing work before any full-product GREEN: T02–T07 controlled PCAP fixtures and independent manual verification, T08 ML anomaly corpus and model, two full T01–T08 runs from clean output directories, hash validation of all PCAP/log/cert/model artifacts, per-stage and total runtime measurement, JSON Schema validation of analyzer output, finding-evidence reference validation, JSON/HTML semantic parity, and formal binary gate G01–G11 evaluation.

## 6. Blockers and deviations

None recorded. One environmental/tool-performance flake (a `tshark_observe` 20-second timeout during a full-suite run under host resource pressure) was observed and is recorded transparently in Section 1c; it is not a functional assertion failure.

## 7. Final POC decision

- **PS159 SecureMailScope is selected/finalized for Team Apex.**
- The selection-grade technical POC is **CLOSED**.
- The demonstrated result is **sufficient to establish technical viability** for proceeding with production implementation.
- This is a **GO/selection decision**, not a claim that the complete product or the complete original POC matrix is GREEN.
- **T02–T08 and formal gates G01–G11 remain UNTESTED.**
- IMAP, POP3, TLS 1.3 invisibility handling, full crypto/X.509 analysis, evidence-backed findings, policy risk, ML anomaly, JSON output and HTML reporting remain production implementation/testing work.
- Policy risk and ML anomaly must remain separate outputs.
- TLS 1.3 certificate information must be marked `not_observable` in passive captures without authorized session secrets.
- Not claimed: phishing detection, email decryption, blocking, live capture, geolocation, SIEM integration, authentication, or PDF export.

Status summary — distinct categories kept explicit:

- T01: PASS
- E2/E3A: PASS
- Selection decision: GO — PS159 selected
- Full T02–T08 / G01–G11 matrix: UNTESTED
- Full product validation: NOT COMPLETE

Next step: production implementation and frontend/backend integration, building on the verified E2/E3A intake/reassembly/classification core and the T01 evidence chain. Further POC fixture generation is not the immediate next action.
