<!-- BEGIN:nextjs-agent-rules -->

# This is NOT the Next.js you know

This version has breaking changes — APIs, conventions, and file structure may all differ from your training data. Read the relevant guide in `node_modules/next/dist/docs/` (resolved from this file's directory; in monorepos the `next` package may not be visible from the repo root) before writing any code. Heed deprecation notices.

This block is written and re-added by `next dev` — verify at `node_modules/next/dist/server/lib/generate-agent-files.js`. Removing it from a diff only re-creates the uncommitted change; committing it with your work keeps the tree clean.

<!-- END:nextjs-agent-rules -->

# SecureMailScope frontend rules

## Scope and authority

- These rules govern `web/**`; the repository-root `AGENTS.md` also applies and
  takes precedence when rules conflict.
- Work only inside `web/**` for frontend milestones. Inspect the existing
  implementation before editing and preserve unrelated user changes.
- Organize work by feature and reusable responsibility. Do not replace the
  application with a giant component or copy a static prototype wholesale.
- Do not stage, commit, push, rebase, or open pull requests unless explicitly
  requested. Do not expand milestone scope or add dependencies without an
  authorized need and written justification.

## Evidence integrity

- The frontend presents backend contract data; it must never derive or invent
  cryptographic conclusions, findings, evidence, scores, or successful API
  results.
- Preserve explicit `unknown`, `not_observable`, `not_assessable`, and
  `not_applicable` states. Ordinary passive TLS 1.3 captures do not expose
  certificate contents without decryption material.
- Keep deterministic Policy Risk separate from ML Anomaly. Never combine them
  into an unsupported score.
- Label all deterministic demonstration data exactly as **Prototype Analysis
  Dataset**. Keep mock and API implementations behind the typed
  `AnalysisDataSource` boundary.

## Implementation standards

- Use the existing Next.js App Router, React, TypeScript, Tailwind CSS,
  shadcn/ui, Zod, Zustand, and react-dropzone foundation.
- Use semantic status colors consistently and never rely on color alone.
- Preserve keyboard access, visible focus, labels, meaningful landmarks,
  readable contrast, reduced-motion compatibility, and responsive behavior.
- Prefer focused reusable components and typed contracts. Do not add
  decorative or random charts; every visualization must communicate real,
  attributable evidence.
- Before handoff, run `npx tsc --noEmit`, `npm run lint`, `npm run build`,
  `npm audit`, and `git diff --check`. Report exactly what ran and update
  `docs/IMPLEMENTATION_STATUS.md` only after a verified milestone state change.
