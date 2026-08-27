# SecureMailScope — POC Result Record

**Record date:** 2026-08-26

**Status:** Partial record — environment/bootstrap milestone PASS; T01 manual verification PASS (corrected attempt; earlier failed attempt preserved). T02–T08 and all binary gates remain UNTESTED.

**Overall recommendation:** Not issued. No GREEN/RED decision is made in this document; the decision step (Step 9) has not run. T01 PASS alone is insufficient for GREEN; every controlled test T01–T08 and every gate G01–G11 must pass.

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

## 3. Controlled matrix T01–T08

| Test | Status | Evidence |
|---|---|---|
| T01 SMTP ECDHE | PASS (corrected) | 23/23 passed, 0 failed; SHA-256 `772d166b…ab086`; 28 packets, received 28, dropped 0; port 2525; STARTTLS frames 9/11; TLS 1.2, 0xC02F, secp256r1; 2 certs; capture+verifier runtimes recorded; earlier attempt preserved |
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

Per the Step 9 decision requirements, still outstanding before any GREEN/RED can be issued: T02–T07 controlled PCAP fixtures and independent manual verification, T08 ML anomaly corpus and model, two full T01–T08 runs from clean output directories, hash validation of all PCAP/log/cert/model artifacts, per-stage and total runtime measurement, JSON Schema validation of analyzer output, finding-evidence reference validation, JSON/HTML semantic parity, and formal binary gate G01–G11 evaluation.

## 6. Blockers and deviations

None recorded.
