# SecureMailScope API — public prototype deployment

SecureMailScope API is a public prototype deployment that performs real, offline
analysis of uploaded PCAP/PCAPNG captures using TShark and the verified V1 analysis
pipeline.

## Scope and source

This packaging uses `deploy/render-v1`, based on tag
`backend-v1-public-deployed` at
`f81bcc43ec660bfa32a40076bfe5c9f146d61339`.
It includes real multipart upload, bounded temporary intake, capinfos/TShark,
SMTP classification and TCP/session reconstruction, STARTTLS transitions,
Chain-of-Proof adaptation, SMTP facts, deterministic policy evaluation, findings,
recommendations, in-memory registration and existing API/artifact retrieval.
The earlier `a262b24` read-only API has no upload/orchestration path and is not
a sufficient deployment baseline.

Backend V2 storage, jobs and unfinished indexed projections stay separate.
No V2 implementation is copied or wired into this application.

- **Live Analysis:** uploads a real capture to this API and waits for its result.
- **Guided Demo:** a separately labelled frontend fixture mode.
- Never silently fall back from Live Analysis to Guided Demo.

## Build and process

`Dockerfile` pins the official Ubuntu 24.04 image by digest and uv **0.12.5** by
version and digest. Ubuntu packages provide Python **3.12**, `tshark` and
`wireshark-common` (which supplies `capinfos`). Both tools require Wireshark
**4.2 or newer**. OS package security revisions can change; record the actual
installed versions for each verified image.

The builder runs `uv sync --locked --no-dev --no-editable`. The final image
copies only the installed environment, including policy YAML and HTML templates.
The default-deny `.dockerignore` admits only backend build inputs and excludes
captures, keys, environment files, local databases, caches and frontend/V2 files.

Runtime user/group is **10001:10001**. Private scratch storage is
`/tmp/securemailscope`, mode **0700**. Application files remain root-owned and
read-only to this user. Wireshark privileged capture configuration is disabled.
Do not grant privileged mode, `NET_ADMIN`, `NET_RAW` or host networking.
Offline file analysis requires none of these privileges.

The image runs `/app/.venv/bin/python -m securemailscope.deployment` directly,
without a shell. PORT is validated before Uvicorn binds **0.0.0.0** with exactly
**one worker**. Uvicorn receives termination signals directly.

Startup checks executable discovery, bounded five-second tool version commands,
minimum versions, directory ownership/0700 permissions and an actual scratch
write. A new scratch directory can be created beneath an existing parent;
unsafe existing directories and symlinks are rejected, never repaired.
A failed check prevents serving traffic. Tool versions are retained in internal
application state, not exposed by the health endpoint.

## Configuration

| Variable | Render value | Validation |
| --- | --- | --- |
| `SECUREMAILSCOPE_ALLOWED_ORIGINS` | `https://secure-mail-scope.vercel.app` | Required explicit comma-separated HTTPS origins |
| `SECUREMAILSCOPE_MAX_UPLOAD_BYTES` | `1048576` | Positive ASCII integer; 1 MiB default |
| `SECUREMAILSCOPE_MAX_REPOSITORY_ENTRIES` | `16` | Positive ASCII integer; 16 default |
| `SECUREMAILSCOPE_MAX_CONCURRENT_ANALYSES` | `1` | Positive ASCII integer; one default |
| `TMPDIR` | `/tmp/securemailscope` | Absolute private directory owned by the runtime user |
| `PORT` | `10000` | ASCII integer in 1–65535 |

Origins trim surrounding whitespace and normalize host case/default ports.
Wildcards, empty entries, credentials, paths, queries, fragments, malformed URLs
and implicit loopback origins are rejected. Loopback HTTP is available only
through explicit Python `local_mode=True` configuration for local tests; the
container entrypoint does not enable it. CORS permits **GET/POST** and
**Content-Type**; middleware handles OPTIONS. Credentials are disabled.
Other origins receive no Access-Control-Allow-Origin permission. CORS is a
browser policy, not authentication: non-browser clients can still call this API.

The existing development/test `create_app()` factory retains its defaults;
the Render composition explicitly applies the smaller limits above.

## Request execution and API

API base path: **/api/v1**. Health: **GET /api/v1/health**:

```json
{"status":"ok","api_version":"v1"}
```

**POST /api/v1/analyses** still waits and returns **201** with the existing
response model. Analysis runs in a standard-library thread so the event loop can
answer health requests. Admission is acquired before multipart parsing and held
through temporary-file cleanup. At configured capacity, excess submissions fail
immediately with **503**, without waiting or spooling their bodies:

```json
{"error":{"code":"analysis_capacity_unavailable","message":"analysis capacity is unavailable"}}
```

There is no analysis queue or polling/job API. Cancellation waits for an already
running analysis thread before deleting its capture or releasing admission.
A completed, validated analysis may register even if the client cancelled;
failed or partial analyses are never registered. Per-tool analysis timeouts
remain V1's 20 seconds; there is no new whole-request deadline.

GET summary, Chain, session events, safe evidence, findings and existing
finding JSON/HTML/PDF endpoints retain their contracts. Policy Risk and
ML Anomaly remain separate. The application starts with an empty bounded
in-memory repository; no fixture data is loaded.

## Verification status — 2026-10-19

- Source-level review, Ruff lint/format and diff checks passed.
- Final review suite: **881 passed, 4 skipped**; focused deployment tests:
  **109 passed**. The skips are the existing frozen-capture tests whose input
  is absent from this isolated worktree.
- A separate local TCP HTTP check ran the actual deployment entrypoint with
  TShark/capinfos **4.2.2** and the existing approved synthetic T01 capture:
  upload 201; health, summary, Chain, session and evidence retrieval 200;
  repeat upload 409; invalid/empty/oversized uploads 415/422/413; scratch
  cleanup passed; an actual process restart returned 404 for the prior result.
  This capture produced no findings. Finding/artifact behavior passed
  separately with injected deterministic test analysis.
- **Docker image build/container verification: pending.**
- **Actual Render deployment verification: pending; no service created.**

## Local image verification

Docker is not currently usable in this WSL setup, and the Windows Docker engine
is unavailable. **Image build and container runtime checks remain pending.**
Do not infer that a successful Python wheel build proves the Docker image builds.

When Docker is available, run from the repository root:

```bash
docker build -t securemailscope-api .
docker run --rm --entrypoint tshark securemailscope-api --version
docker run --rm --entrypoint capinfos securemailscope-api --version
docker run --rm --name securemailscope-api -p 18182:10000 \
  -e SECUREMAILSCOPE_ALLOWED_ORIGINS=https://secure-mail-scope.vercel.app \
  -e SECUREMAILSCOPE_MAX_UPLOAD_BYTES=1048576 \
  -e SECUREMAILSCOPE_MAX_REPOSITORY_ENTRIES=16 \
  -e SECUREMAILSCOPE_MAX_CONCURRENT_ANALYSES=1 \
  securemailscope-api
```

Verify non-root UID, private scratch permissions, health during real analysis,
concurrent-request 503, all retrieval/artifact routes, rejected extensions,
empty and oversized uploads, repeated-upload 409 and loss of results after
a stop/start. Finding routes require a capture with a real supported finding.

## Render setup

After separately authorized review, commit and push, create one **Web Service**:

| Field | Value |
| --- | --- |
| Name | `securemailscope-api` |
| Repository | `AnsariTazeem/SecureMailScope` |
| Branch | `deploy/render-v1` |
| Root directory | Repository root (leave blank) |
| Runtime | Docker |
| Dockerfile / context | `./Dockerfile` / `.` |
| Region | Singapore |
| Plan / instances | Free / 1 |
| Health check | `/api/v1/health` |
| Auto-deploy | Off |
| Docker command override | Leave blank; use image CMD |
| Environment | All six variables in the configuration table |

`render.yaml` expresses this setup. It creates no database, persistent disk,
worker, cron or private service. If using Blueprints, select this deployment
branch for the Blueprint; the service inherits it. The branch is deliberately
not hardcoded into application behavior.

## Post-deployment checks and frontend integration

Use only an already approved non-sensitive synthetic capture. Replace the
example host and file path before running these commands:

```bash
API=https://YOUR-SERVICE.onrender.com
curl --fail-with-body "$API/api/v1/health"
curl --fail-with-body -F 'capture=@/path/to/approved-synthetic.pcapng' \
  "$API/api/v1/analyses"
# Set ANALYSIS_ID to the ID from the 201 response.
curl --fail-with-body "$API/api/v1/analyses/$ANALYSIS_ID"
curl --fail-with-body "$API/api/v1/analyses/$ANALYSIS_ID/chain"
curl -i -X OPTIONS "$API/api/v1/analyses" \
  -H 'Origin: https://secure-mail-scope.vercel.app' \
  -H 'Access-Control-Request-Method: POST' \
  -H 'Access-Control-Request-Headers: content-type'
curl -i -H 'Origin: https://unknown.example' "$API/api/v1/health"
```

Expect exact-origin permission for the Vercel preflight and no origin permission
for the unknown origin. Retrieve session events and evidence IDs from the Chain;
retrieve finding details and JSON/HTML/PDF artifacts when findings are present.

Do not change the frontend API URL until the actual Render service passes
deployment verification, including the real-upload and retrieval checks above.
Only then set Vercel's **NEXT_PUBLIC_API_BASE_URL** to the Render base URL
(without `/api/v1`), then rebuild/redeploy Vercel. Test upload and every
analysis screen in incognito. Preserve **https://secure-mail-scope.vercel.app**.
Keep Guided Demo separate and explicitly labelled; never conceal a Live
Analysis failure by silently substituting fixture data.

## Operational limitations and rollback

This is a public prototype, not a confidential production service. Use only
non-sensitive synthetic captures. There is **no authentication, tenant
isolation, durable storage or queue**. Stored analyses are shared within this
process and disappear on restart, redeploy or free-host spin-down. Capacity is
16 analyses with no eviction. Repeated identical upload can return **409**.
A fresh process starts empty.

The production analyzer is SMTP-focused; complete IMAP/POP3 support and
production ML execution are absent. No live capture or email decryption is
added, and no unobservable TLS/certificate information is fabricated.

Render Free has **512 MB** memory; the 1 MiB input and concurrency limits are
precautions, not proof against out-of-memory failures. Validate the actual
image with representative captures before relying on it. Free services spin
down after **15 minutes** idle and can take about **one minute** to wake.
Cold starts can exceed frontend/network request timeouts. Free usage limits
also apply; two months of uninterrupted availability is not guaranteed.

Keep auto-deploy off until image and service checks pass. The source rollback
baseline is **f81bcc43ec660bfa32a40076bfe5c9f146d61339**; it predates Docker
packaging, so it is not a directly redeployable Render image. Before a later
deployment, record the first verified packaging commit and image digest as the
operational rollback target. No deployment or cloud resource was created here.

References: [Render Docker](https://render.com/docs/docker),
[Blueprint specification](https://render.com/docs/blueprint-spec),
[Free services](https://render.com/docs/free),
[Compute plans](https://render.com/docs/compute-plans),
[uv Docker integration](https://docs.astral.sh/uv/guides/integration/docker/).
