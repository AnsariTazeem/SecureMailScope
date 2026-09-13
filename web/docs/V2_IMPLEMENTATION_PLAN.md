# SecureMailScope V2 — content and workflow changes

## Authoritative starting point

Source archives supplied by the user on 6 September 2026 identify their Git commits through their tar PAX headers:

- Frontend: `da8c4b7856a4ff1a6d60b8365a4edb91badb19ed`.
- Backend: `f81bcc43ec660bfa32a40076bfe5c9f146d61339`.

These are source snapshots without `.git` history. No branch, commit, push or deployment was performed here. The original uploaded V1 archives are preserved. The user reports that this baseline is deployed and upload-tested; this work does not independently re-certify that deployment.

Root `AGENTS.md`, `MASTER_PROMPT.md`, `context/ui-context.md` and portions of `context/progress-tracker.md` in the frontend still describe earlier POC/backend work, a frozen frontend and excluded PDF. Those historical scope statements conflict with the supplied implementation and the user's explicit V2 authorization in this conversation. The current task authorizes V2 frontend development; frozen POC evidence, requirements and backend contracts remain unchanged. Finding-level PDF already exists in the supplied backend. This document records the current frontend task without rewriting historical POC records.

## Approved product direction

- Latest user correction: preserve V1 styling and colour tokens. Classic white is a possible later visual direction, not authorization to change the palette now. Dark mode and a broader visual redesign are deferred. The colourful PPT illustration is not a product style reference.
- Start/upload has no results sidebar. Keep actual upload validation and authorization intact.
- Four main destinations: Overview, Sessions, Recommendations, Report. New analysis is a separate action; Analysis details contains capture provenance and tool versions.
- Session investigation: Timeline, TLS & Certificates, Findings & Evidence.
- Reuse V1 React Flow graph, topology, evidence relationships, controls and on-demand inspector. Keep the graph full width; do not create a permanently visible parallel inspector.
- Text evidence is a secondary searchable route into exact records, not a competing primary findings view.
- Real captures use the real API. Demo uses the explicit Prototype Analysis Dataset. No error-to-demo fallback, invented crypto state, combined policy/ML score, or production ML claim.

## Slice 1 implemented

1. V1 colour tokens and surface colours preserved; four primary destinations, sidebar-free Start, skip link and compact mobile header.
2. Analysis details drawer with validated identity/source, capture hashes, timestamps, tool/rule versions, warnings and analysis limitations.
3. Overview moves detailed capture provenance into the drawer and retains the session investigation entry point.
4. URL-backed session tabs. Existing sections and exact evidence inspection remain accessible; hidden panels are kept mounted to support investigation continuity.
5. Existing React Flow graph embedded and locked to the current session; V1 filters, labels, node/edge styling and canvas presentation preserved. Original standalone graph route remains available for old links.
6. Searchable evidence records, expandable session metadata and finding detail, and links to session-specific remediation.
7. Dedicated Recommendations route: declared action and verification steps, supporting findings and evidence links, explicit unavailable-session state. Anomaly tab includes a labelled illustrative workflow for demo only, with no invented score.
8. Compare sessions is available from Sessions when at least two sessions exist. Existing finding, compare, report and proof routes remain intact.

The backend, API adapters, upload workflow, result contracts, package manifest/lock and prototype evidence fixture were not changed. No dependency was added to the application.

## V2 release-checkpoint status

The authorized content-and-workflow implementation is complete. Overview
cleanup and Analysis-details navigation are complete, with the latter verified
in the browser. Session Timeline, TLS & Certificates, Findings & Evidence,
Recommendations, Report consistency and print hierarchy are complete. Proof-map
Slice A and Slice B are implemented and browser-accepted.

The final audit verdict is **READY WITH DOCUMENTED LIMITATIONS**. No
application-blocking defect remains. The remaining unverified areas are the real
backend workflow and live backend finding artifacts, native Windows print-dialog
parity, touch gestures, screen-reader quality and unusually large future graphs.
These are release limitations, not claims of completed verification.

The normal Turbopack production build fails with an environment-specific
`EPERM`; the webpack production build passed. The deployed V1 remains unchanged:
this V2 checkpoint has not been deployed. Broader visual redesign and dark mode
remain deferred.

## Backend audit: implemented versus missing

Verified by source inspection, not by a new live packet-analysis run:

- `orchestration/service.py` composes intake/analyzer, Chain adapter, SMTP facts, policy evaluation and registration. `api/uploads.py` supplies the real upload boundary.
- `chain/poc_adapter.py` still sets `crypto_observations=[]`. SMTP transition evidence does not establish negotiated cipher, key exchange, Forward Secrecy or certificate validity.
- `chain/policy/rules/smtp-starttls-1.0.0.yaml` provides the current SMTP policy pack. Richer crypto rules need verified observations first.
- `presentation/renderers.py` and the read-only API expose finding-level HTML/PDF and canonical JSON. Frontend `report-export-actions.tsx` already downloads Chain JSON and finding HTML/PDF, with browser print for a full report.
- The repository is in memory. Retained real analysis IDs depend on the lifetime/capacity of the running backend; durable storage is separate work.

Next backend slice should establish bounded, evidence-linked negotiated TLS observations before expanding rule coverage. Certificate extraction/validation follows with explicit trust, identity and capture-time prerequisites. TLS 1.3 certificate contents remain unobservable without authorized session secrets. IMAP/POP3, production ML, durable jobs/storage, live capture and integrations are later milestones.

## Post-checkpoint validation

The V2 tree is ready for its release checkpoint while deployed V1 remains the
unchanged rollback point. Before any later deployment, validate the real backend
workflow and live finding artifacts, native Windows print-dialog parity, touch
gestures, screen-reader quality and representative larger graphs. Backend TLS,
certificate, protocol and ML capability expansion remains a separate workstream
and must not be inferred from this frontend checkpoint.

## Proof-map Slice A — implemented 12 September 2026

The current explicit request supersedes the earlier restriction to session
scoping alone. Slice A adds neutral titles, supplied values, distinct provenance
and qualified event status, safe evidence previews, wrapped fixed-size cards,
meaning-first inspectors and a selection-only clear action. It keeps the V1
white/cream surfaces, charcoal controls, semantic graph colours and existing
lanes/relationships. No Slice B traversal or new graph lane is included.

Geometry: 260 × 132 cards, 48px column gaps and 28px row gaps share one helper.
A 260 × 156 candidate was inspected in Chrome; a browser comparison found the
132px candidate accommodated demo content with 8px vertical padding. A long
DOM-text stress probe also kept two title/value lines without overlap. Full
fit remains an overview, particularly at 390px; existing zoom and inspection
provide detailed reading. Selection never changes dimensions or layout identity.

The filter now means **Provenance / event state**. Unreachable `unknown`,
`not_present` and `not_assessed` options were removed; these remain distinct
supplied result values. `session_secrets_required` is selectable explicitly.
Event status qualifies observability (inferred observed-evidence events display
Derived; incomplete/unobservable event statuses retain their qualification).
Filtering still clears selection and initializes the filtered viewport; it
never lays out the remaining nodes again or synthesizes edges.

Close/Escape dismiss inspection and retain immediate-neighbour highlighting.
Clear selection removes it without changing pan/zoom. Existing pane clearing,
Fit, Reset and zoom controls remain. The inspector uses the existing Sheet,
a visible Close control and an explicit initiating-element focus target.
Exact source values/metadata and owned limitation details remain expandable;
evidence previews use approved safe excerpts/source fields, never raw packet
normalized values.

Production webpack build, frontend static checks, focused regression checks,
and headless Chrome desktop/390px graph checks passed. The normal Turbopack
build still fails at its CSS worker port binding; this is not a source PASS.
See IMPLEMENTATION_STATUS.md for commands, browser evidence and limitations.
This Slice A record describes its original boundary. Slice B was subsequently
authorized and is recorded below.

## Proof-map Slice B — implemented 12 September, accepted 13 September 2026

Finding selection now starts an investigation while inspection remains separate.
The complete, validated graph is traversed upstream before filters through only
`finding.fact_ids`, `finding.evidence_ids`, the three declared fact-source
fields, and event/observation evidence IDs. Evidence is terminal. Chronology,
session structure, classification, anomaly, and rule-evaluation links are not
traversed. Rule-evaluation relationships remain available as technical context
without invented evaluation nodes or replacement canvas edges.

The traversal rejects duplicate or malformed eligible relationships, unresolved
canvas references, fact-source cycles, and cross-session/capture endpoints.
Shared evidence is visited once and is never followed outward into another
dependent. For the demo finding `fnd_475510c505d60661` in
`ses_3ac703c890cdeada`, regression and live-browser identity checks confirm
9 nodes including the finding and 10 existing canvas relationships. The
unavailable TLS-version observation remains evidence-free and retains its
`session_continued_in_plaintext` limitation.

Close and Escape dismiss the inspector while retaining the active finding.
Supporting node or edge inspection does not replace that context. Entity/state
filters intersect the complete support set, retain positions, and report hidden
node/relationship counts; policy links without canvas endpoints are counted
separately. Fit selection appears only during an investigation, targets visible
support, and disables when none is visible. Clear selection removes investigation
and inspection without changing the viewport. Session/analysis identity changes
clear stale context. Investigation and inspection remain outside `layoutKey`,
preserving initial fit and kept-mounted tab-return pan/zoom behavior.

Acceptance on 13 September used the existing production artifact and isolated
Chrome at desktop and 390px. The exact highlight, inspector/Close/Escape flow,
nested evidence focus return, filtering/restoration, zero-visible-support state,
explicit Fit selection, Clear, session-scope invalidation, and embedded tab
return all passed. The source regression and mocked fit scripts also passed.
Details and screenshot paths are recorded in `IMPLEMENTATION_STATUS.md`.
