# SecureMailScope — UI Context

## Current status

No UI or repository has been created. UI work is not part of the first technical POC stages.

## POC interface

The POC is CLI-first. It produces canonical JSON plus one minimal static HTML report rendered from that exact JSON.

The minimal HTML must show:

- input filename/hash and capture/tool provenance;
- session protocol, endpoints, stream, timing, and reconstruction status;
- STARTTLS/STLS outcome and timeline evidence;
- TLS version, cipher, key establishment, Forward Secrecy, and observability;
- certificate facts/validation or the exact reason they are unavailable;
- prioritized deterministic findings with evidence and mitigation;
- policy-risk/posture scores and a clearly separate ML-anomaly score;
- limitations, unknowns, and incomplete-capture warnings.

## POC presentation rules

- Render HTML only from `report.json`; never recompute findings in the template.
- Work locally without JavaScript or network access.
- Prefer a simple table/card layout.
- Use semantic HTML, adequate contrast, and text labels; never rely only on colour.
- Make `unknown`, `partial`, and `not_observable_encrypted_tls13` visibly distinct.

## Deferred final UI

If PS159 is selected, the final solution must add the official interactive visualization dashboard and PDF report. A reasonable later choice is Next.js/React consuming a FastAPI endpoint backed by the reusable Python analysis core.

Do not design or build React, Next.js, authentication, charts, uploads, dashboards, or a design system before the POC core passes.
