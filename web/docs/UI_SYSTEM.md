# UI System

## Forensic interface principles

SecureMailScope uses a restrained forensic-workbench visual language: dense
enough for evidence review, calm enough for long sessions, and explicit about
uncertainty. Hierarchy, copy, borders, icons, and labels carry meaning; color is
supporting information only.

The supplied Start Analysis HTML is a visual and content reference for
composition, hierarchy, spacing, typography, borders, upload structure,
assessment scope, and responsive intent. It is not production source code.
Generated scripts, inline positioning, fake behavior, and fake security results
must never be copied into the application.

## Semantic colors

| Meaning | Treatment |
| --- | --- |
| Neutral/evidence | white and neutral surfaces, dark text, neutral borders |
| Active/selected | high-contrast neutral fill or strong left rule |
| Success/observed pass | green accent plus icon and text label |
| Warning/limited observability | amber accent plus explanatory copy |
| Error/failure | red accent plus error title and actionable text |
| Informational/prototype | blue or neutral notice plus explicit dataset label |
| Unknown/not observable | neutral or amber treatment with the exact state written out |

Semantic colors must not be reassigned for decoration. Policy Risk and ML
Anomaly require separate labels, legends, and scales whenever they are shown.

## Foundations

- Typography uses a compact system sans-serif stack for interface text and a
  monospace stack for identifiers, hashes, protocol values, and evidence IDs.
- Page spacing follows a small consistent rhythm; major regions use generous
  separation while related controls remain grouped.
- Borders are thin and neutral. Radius and shadow are modest so cards read as
  evidence containers, not promotional tiles.
- Headings use sentence case except compact navigation and metadata labels,
  which may use tracked uppercase text.

## Navigation and containers

Desktop navigation uses a persistent left rail and header. Small screens use a
horizontally scrollable primary navigation. The active route is indicated by
text, contrast, and shape—not color alone. Result destinations remain disabled
until an analysis ID exists.

Cards have a clear title region, content region, and optional action/footer.
Tables use semantic headers, aligned values, readable wrapping, and an
accessible small-screen alternative when horizontal scrolling would obscure
relationships. Master-detail layouts keep the selected row identifiable while
the detail pane preserves evidence context.

## Status and evidence patterns

- Status badges pair concise text with semantic color.
- Evidence references use stable identifiers and link to their source context
  when the destination exists.
- `unknown`, `not_observable`, `not_assessable`, and `not_applicable` are shown
  verbatim with an explanation when needed.
- Passive TLS 1.3 certificate limitations are disclosed wherever certificate
  fields could otherwise appear absent or misleading.
- Empty states explain whether data is absent, unavailable, out of scope, or
  not yet implemented. Loading uses stable skeletons or progress. Errors state
  what failed without implying a successful analysis.

## Upload pattern

The upload region supports click, keyboard, and drag/drop selection. It shows
accepted extensions and byte limits before selection, clear drag/rejection
feedback, one selected-file card, replace/remove actions, validation results,
and a separate authorization control. Starting remains disabled until a valid
input and authorization are present. The prototype option is visually distinct
and always labelled **Prototype Analysis Dataset**.

## Accessibility and responsive behavior

Use semantic landmarks, headings, labels, native controls, meaningful button
names, visible focus rings, sufficient contrast, and announced error text.
Interactions must work without a pointer. Do not encode meaning in hover alone.
Respect reduced motion and avoid movement that interrupts evidence reading.

Layouts collapse from multi-column to single-column without changing reading
order. Sticky supporting panels become normal-flow content on smaller screens.
Navigation, tables, identifiers, and long filenames must wrap or scroll without
clipping controls.

## Visualizations

Use a visualization only when it makes a real evidence relationship, sequence,
or comparison easier to understand than prose or a table. Values must come from
validated result data and retain evidence attribution. Do not render decorative,
random, or synthetic charts. Missing observations must not be converted to
zeros.

## Milestone screenshot mapping

| Milestone | Approved visual intent |
| --- | --- |
| F1 | Start Analysis composition: workflow steps, upload card, validation and authorization, right-side assessment scope, evidence boundary note, responsive stacking. |
| F2 and later | No screenshot-driven implementation is approved in F1. Each later milestone must map its own reference to validated contract fields before implementation. |
