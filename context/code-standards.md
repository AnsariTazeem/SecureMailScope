# SecureMailScope — Code Standards

**Applies after implementation begins. No code exists yet.**

## Python rules

- Target Python 3.12 only for the POC. Broader compatibility is post-selection work.
- Use `pathlib.Path`, complete type hints, small pure normalization functions, and explicit enums for protocols, outcomes, and observability.
- Use Pydantic models at component boundaries. Reject contradictory reports rather than silently coercing them.
- Keep packet/tool I/O, protocol state machines, cryptographic analysis, scoring, and reporting separate.
- Avoid mutable global state so repeated analyses remain deterministic.
- Use stable IDs, sorted output, UTC ISO-8601 timestamps, and explicit schema/rule/model versions.
- Convert failures into typed pipeline errors at component boundaries. Do not silently swallow exceptions.

## External-command rules

- Invoke TShark and OpenSSL with an argument list and `shell=False`.
- Set timeouts and capture bounded stdout/stderr.
- Record command name, exit code, stage, and safe diagnostics.
- Never expose environment secrets, credentials, private keys, or signed URLs.
- Query installed TShark fields/version instead of assuming that every release uses identical field names.

## Packet and protocol rules

- Use TShark two-pass TCP/protocol reassembly; do not implement TCP sequence reconstruction.
- Do not hardcode fixture paths, ports, IP addresses, stream numbers, frame numbers, cipher names, or certificate facts in analyzer logic.
- Classify SMTP/IMAP/POP3 using content, direction, and state. Ports are hints only.
- Preserve unknown/incomplete values; absence is not automatically a vulnerability.
- Retain raw values alongside normalized TLS/certificate values.
- Never claim decryption of encrypted email content or TLS handshake portions without provided secrets.

## Evidence and privacy rules

- Every cryptographic fact must link to precise evidence.
- Every policy finding must reference resolvable evidence IDs.
- Do not store credentials, email body, or private message content in report JSON, HTML, logs, snapshots, or error messages.
- For protocol proof, retain command type, length, direction, stream, frame, and safe fixture markers only.
- Hash PCAPs, endpoint logs, certificate files, manifests, and ML models with SHA-256.

## Ground-truth rules

- Expected values come from controlled fixture configuration, endpoint/OpenSSL logs, certificate manifests, capture time, and pinned hashes.
- The analyzer must never write or update `fixtures/ground_truth.json`.
- Never regenerate expected test output from current analyzer output.
- If independent truth and analyzer output differ, the test fails until the cause is established.

## Testing rules

- Every POC gate needs controlled positive evidence and the relevant negative/incomplete behaviour.
- Test generic PCAP input, not a hardcoded fixture-only path.
- Run the full matrix twice to prove repeatability.
- HTML tests compare semantic values and session IDs with canonical JSON; HTML is never a second analysis path.
- ML tests prove deterministic pipeline separation on controlled data only, not real-world accuracy.

## Planned quality commands

```bash
uv run ruff check .
uv run ruff format --check .
uv run pytest -q
```

Do not mark a work unit complete merely because code compiles. It must agree with controlled PCAP ground truth.
