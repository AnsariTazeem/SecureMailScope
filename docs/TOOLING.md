# SecureMailScope POC — Tooling Decision Record

## 1. Decision summary

Use a small, product-grade toolchain that improves correctness and reproducibility without consuming the one-day technical timebox.

Core POC workflow:

```text
WSL2 Ubuntu
  + Git (GitHub remote when available)
  + Python 3.12 managed by uv
  + TShark/Wireshark + OpenSSL + tcpdump/dumpcap
  + Pydantic/Typer/cryptography/Jinja2/scikit-learn
  + Ruff + pytest

Conditional quality layer after local proof:
  pre-commit + GitHub Actions + CodeRabbit + pip-audit
```

CodeRabbit is useful, but it is not mandatory for packet correctness. It reviews code and pull requests; TShark/OpenSSL ground truth and automated PCAP tests decide whether the POC passes.

## 2. Tool-selection principles

- A tool must directly improve correctness, reproducibility, review quality, or speed.
- A tool that takes longer to configure than the risk it removes is deferred.
- No tool may become the source of cryptographic ground truth unless it is part of the explicit controlled evidence contract.
- Never send real or sensitive PCAPs, private keys, credentials, key logs, or sensitive output to an AI/SaaS tool. A controlled synthetic PCAP may be committed only after confirming that it contains no sensitive data; access granted to a repository-connected service is also access to committed files.
- Prefer one tool per job; avoid overlapping linters, formatters, test runners, and project managers.
- Freeze versions/hashes used in the final evidence run.

## 3. Mandatory foundation tools

### 3.1 WSL2 Ubuntu

**Decision:** Required development environment on Windows.

Use the Linux filesystem under `~/projects/SecureMailScope`, not `/mnt/c`, so Linux packet tools, permissions, file watchers, and Python environments behave consistently.

Use `sudo` only for system-package installation and controlled capture permissions—not for creating/editing project files or running the analyzer.

### 3.2 Git and GitHub

**Decision:** Git is required. A private/scoped GitHub remote is recommended for backup, pull-request review, and optional CI, but GitHub availability is not a technical POC gate.

Purpose:

- recoverable history;
- checkpoint commits;
- pull-request review;
- CI status;
- final commit hash in POC evidence.

Minimal branch strategy for the POC:

```text
main       verified documentation/checkpoints
poc/core   one working branch for the technical POC
```

Use small checkpoint commits on `poc/core`. Create a pull request only when it provides useful human/automated review; do not create branches or PRs for every tiny file.

### 3.3 Python 3.12

**Decision:** Required core language.

Why:

- cryptography and X.509 libraries;
- typed data/report modelling;
- strong test tooling;
- scikit-learn integration;
- simple local CLI/report pipeline.

Node/Express is not selected for packet/crypto processing. If PS159 is selected, FastAPI can expose this Python core while the developer uses React/Next.js for the final dashboard.

### 3.4 `uv`

**Decision:** Required project/dependency manager instead of a manually maintained `venv + pip freeze` workflow.

Why:

- creates and synchronizes the project environment;
- stores requirements in `pyproject.toml`;
- produces a cross-platform exact `uv.lock` that should be committed;
- `uv run` checks environment/lock consistency before commands.

Repository rules:

- Commit `pyproject.toml`, `.python-version`, and `uv.lock`.
- Ignore `.venv/`.
- Use `uv sync --locked` for verified/final runs.
- Never edit `uv.lock` manually.

Official references: [uv projects and lockfile](https://docs.astral.sh/uv/guides/projects/), [uv installation](https://docs.astral.sh/uv/getting-started/installation/).

### 3.5 TShark/Wireshark

**Decision:** Required packet-dissection and TCP/TLS-reassembly engine.

TShark provides machine-readable offline analysis. Its `-2` option performs two-pass analysis, including future-dependent fields and correct reassembly-frame dependencies. [TShark manual](https://www.wireshark.org/docs/man-pages/tshark.html)

Use:

- TShark CLI in the analyzer and automated/manual evidence commands.
- Wireshark GUI optionally for visual inspection and demo screenshots.

Do not:

- parse Wireshark GUI output;
- require the GUI for analyzer operation;
- hide TShark commands/versions behind an opaque wrapper.

### 3.6 OpenSSL 3.x

**Decision:** Required independent endpoint/certificate truth tool.

Use for:

- controlled CA/server certificates;
- forced TLS endpoint configuration;
- negotiated version/cipher logs;
- fingerprints and certificate inspection;
- chain validation at capture time with `verify -attime`.

OpenSSL truth complements PCAP evidence; it does not replace the analyzer's packet evidence.

Reference: [OpenSSL verify](https://docs.openssl.org/3.0/man1/openssl-verify/).

### 3.7 tcpdump or dumpcap

**Decision:** Required only for controlled fixture generation.

Use to capture local loopback traffic created by the fixture scripts. Product analysis never starts live capture. Capture commands/configuration and version become fixture provenance.

### 3.8 Standard command-line evidence tools

**Decision:** Required and intentionally boring.

- `sha256sum`: PCAP/log/certificate/model hashes.
- `jq`: inspect/compare canonical JSON.
- `file`: input type diagnostics.
- `/usr/bin/time`: reproducible runtime measurement.
- `editcap`: produce controlled truncation from a known complete fixture when appropriate.

## 4. Runtime Python dependencies

| Dependency | Purpose | Constraint |
|---|---|---|
| `pydantic` | Typed domain/report validation and schema generation | Models only; no packet I/O |
| `typer` | CLI | Thin boundary |
| `cryptography` | X.509 DER parsing and cryptographic facts | OpenSSL still verifies controlled chain independently |
| `jinja2` | Minimal HTML | Render from canonical JSON only |
| `jsonschema` | Explicit report-schema validation | Fail report on invalid structure/references |
| `PyYAML` | Versioned policy rule loading | Safe loader only; no executable YAML |
| `scikit-learn` | IsolationForest proof | Controlled small corpus; no accuracy claim |
| `joblib` | Frozen model serialization | Record SHA-256 |

Do not add a dependency until the active feature requires it.

## 5. Code-quality and test tools

### 5.1 Ruff

**Decision:** Required linter and formatter.

Ruff supplies both a Python linter and formatter, avoiding overlapping Black/isort/Flake8 installations. [Ruff documentation](https://docs.astral.sh/ruff/), [formatter](https://docs.astral.sh/ruff/formatter/)

Required checks:

```text
uv run ruff check .
uv run ruff format --check .
```

Use automated fixes deliberately; review security/logic changes rather than blindly applying every suggestion.

### 5.2 pytest

**Decision:** Required test runner.

Pytest fixtures provide explicit, modular, repeatable setup appropriate for PCAP/trust-store/model test resources. [pytest fixtures](https://docs.pytest.org/en/stable/explanation/fixtures.html)

Test layers:

- unit;
- TShark adapter sample;
- PCAP integration;
- ground-truth comparison;
- schema/evidence integrity;
- JSON/HTML parity;
- ML repeatability.

### 5.3 pre-commit

**Decision:** Conditional after Ruff/tests run successfully once. Add it only if setup is quick and does not delay a technical gate.

Pre-commit runs fast checks before commits so reviews focus on logic instead of whitespace/format errors. [pre-commit documentation](https://pre-commit.com/)

Planned hooks:

- trailing whitespace/end-of-file checks;
- YAML/TOML validation;
- large-file check;
- private-key detection;
- Ruff check;
- Ruff format check.

Do not put the full PCAP matrix in every pre-commit hook; run fast unit/quality checks on commit and the full suite at explicit checkpoints and, if enabled, in CI.

## 6. GitHub Actions CI

**Decision:** Recommended after T01 and the first local automated test pass. Skip or defer it if runner/YAML setup threatens the one-day timebox; lack of CI alone does not fail a technical gate.

GitHub Actions can run builds, linting, security checks, and tests on pushes/pull requests and surface results in the PR. [GitHub CI documentation](https://docs.github.com/en/actions/get-started/continuous-integration), [building/testing Python](https://docs.github.com/en/actions/tutorials/build-and-test-code/python)

POC CI job:

1. Checkout.
2. Set up pinned Python 3.12 and `uv`.
3. Install TShark/OpenSSL for offline analysis.
4. `uv sync --locked`.
5. Ruff lint/format check.
6. Pytest on committed controlled fixtures.
7. JSON Schema/evidence-reference/parity checks.
8. Optional dependency audit.

CI must analyze pre-generated controlled PCAPs. It does not need capture privileges and must not regenerate ground truth.

Why not set it up first: debugging YAML/runners before proving T01 wastes the critical first 90 minutes.

## 7. CodeRabbit decision

### Is CodeRabbit useful?

Yes, as a secondary reviewer after a meaningful pull request exists. CodeRabbit provides automated, context-aware PR review and can be configured through a root `.coderabbit.yaml`. [CodeRabbit review overview](https://docs.coderabbit.ai/guides/code-review-overview), [YAML configuration](https://docs.coderabbit.ai/getting-started/yaml-configuration)

### When we will use it

- Not before repository/context setup.
- Not during the first T01 manual evidence sprint.
- First use: PR containing the generic analyzer/session/TLS boundary and tests.
- Second/final use: PR containing policy/ML/report integration.

### What it should review

- unsafe subprocess/path handling;
- hardcoded fixture assumptions;
- typing/error-boundary problems;
- protocol state-machine edge cases;
- tests that accidentally use analyzer output as truth;
- TLS 1.3/cipher/key-exchange confusion;
- policy/ML coupling;
- evidence-reference integrity;
- credential/private-key leakage;
- missing negative tests.

### What it cannot prove

- whether the PCAP really contains the expected stream/frames;
- whether TShark extracted the correct installed-version fields;
- whether endpoint truth and PCAP agree;
- whether a certificate was observable in passive TLS 1.3;
- whether the POC gates pass.

Those are resolved by controlled evidence and tests.

### Safety and configuration

- Review repository permissions before installing any GitHub App.
- Connect only the SecureMailScope repository, not every repository, where the provider allows scoped access.
- Never commit/upload private fixture keys, key logs, real/sensitive PCAPs, credentials, or sensitive output.
- Add a version-controlled `.coderabbit.yaml` only after the first analyzer PR.
- Exclude binary/generated paths such as PCAPs, models, key logs, and outputs from review noise.
- Give path-specific instructions for `src/`, `tests/`, `policy/`, and `docs/`.
- Treat comments as hypotheses to verify, not automatic changes.

CodeRabbit can auto-review eligible PRs and supports version-controlled configuration. Its configuration should request concise, assertive findings rather than style noise. [Automatic review controls](https://docs.coderabbit.ai/configuration/auto-review), [configuration reference](https://docs.coderabbit.ai/reference/configuration)

## 8. AI coding tools

**Decision:** Use one primary AI coding agent at a time and a second reviewer only at checkpoints.

Required workflow:

1. AI reads the always-load files and task-specific documents defined by the routing table in `MASTER_PROMPT.md`.
2. Developer assigns one bounded feature from `FEATURE_BREAKDOWN.md`.
3. AI states acceptance criteria and edits only that unit.
4. AI runs relevant checks and reports actual output.
5. Developer/second reviewer verifies against manual ground truth.
6. Update progress tracker and commit.

Do not let two AI agents edit the same branch concurrently without an explicit ownership split. Do not accept “tests should pass”; require actual commands/results.

Never paste or upload real/sensitive PCAPs, private keys, key logs, credentials, or sensitive output to an AI service. A repository-connected service may access a committed controlled synthetic PCAP only after it has been confirmed non-sensitive. Prefer sanitized TShark fields, hashes, controlled excerpts, schemas, and code.

## 9. Dependency/security audit

### pip-audit

**Decision:** Recommended once at final verification; do not let it displace core tests.

Purpose: audit the resolved Python environment for known dependency vulnerabilities. Any finding is recorded and assessed; an unavailable fix or irrelevant transitive finding is not silently ignored.

Official project: [pip-audit](https://pypa.github.io/pip-audit/).

### Not selected for the POC

- SonarCloud/SonarQube: overlaps with Ruff/review and adds setup time.
- Snyk: additional account/integration; dependency audit is sufficient for the POC.
- GitHub CodeQL: valuable for a longer product cycle, disproportionate for the eight-hour proof.
- Dependabot/Renovate: useful after selection, unnecessary during a one-day locked build.

## 10. IDE/editor decision

Use an editor that operates inside WSL and uses the WSL Python environment:

- Recommended: VS Code with WSL integration or PyCharm with a WSL interpreter.
- Acceptable: any editor/AI agent whose terminal and files are inside `~/projects/SecureMailScope`.
- Avoid: editing a second Windows copy while commands run against the WSL copy.

The interpreter must resolve to the project's `.venv`/`uv` environment, not Windows Python.

## 11. Project-management decision

Use repository-native tracking only:

- `context/progress-tracker.md` for current truth;
- `FEATURE_BREAKDOWN.md` for backlog;
- Git branches/commits/PRs for changes;
- `POC_RESULT.md` for final evidence.

Do not add Jira, Trello, Linear, Notion, or a GitHub Project board for an eight-hour solo POC. The context documents already provide the required control.

## 12. Tools explicitly deferred

| Tool/category | Reason deferred |
|---|---|
| Docker/Compose | Native WSL tools are simpler; no deployment target yet |
| FastAPI/Postman/Swagger | No API in the POC |
| React/Next.js/Figma dashboard | Interactive UI deferred until selection |
| PostgreSQL/Prisma | No persistence requirement in POC |
| Sentry/Datadog/Prometheus | No deployed service to monitor |
| MLflow/DVC | Tiny frozen controlled corpus; hashes/manifests are sufficient |
| Scapy/custom dissector | TShark plus controlled sockets should prove the requirement first |
| Zeek | Additional framework does not replace required email/TLS evidence chain |
| PDF tools | Official final feature, explicitly deferred for kill test |

## 13. Adoption order

```text
Before code:
  WSL + Git/GitHub + context/docs

Environment step:
  uv + Python + TShark/OpenSSL/capture tools + shell evidence tools

First implementation:
  runtime dependencies + Ruff + pytest

After first tests, if quick:
  pre-commit (conditional)

After T01/core pass, if useful:
  GitHub Actions (conditional)

After first meaningful PR, if installed:
  CodeRabbit (conditional)

Final verification:
  full matrix twice + pip-audit if time permits
```

Adding tools in this order prevents tooling work from masking the primary technical kill test.
