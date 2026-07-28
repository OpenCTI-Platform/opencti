# Implementation Roadmap — OpenCTI

GENERATED SKELETON — scaffolded once by `pnpm generate:fds-migration --product opencti --write-to-product`.
Sections below are then maintained by agents as work progresses;
re-running the generator does NOT overwrite this file (only creates it if
missing).

## Phase 1 — Tokens (current chantier)

Upstream tracking: filigran-design-system `ROADMAP.json` `implementations[]`,
id `tokens-opencti`. Mirror major state changes back there (AGENTS.md
"Roadmap — règles d'usage": owner before branch, status in the same commit
as the work).

- [ ] Bridge generated (`opencti-platform/opencti-front/src/components/fds-tokens.generated.ts` present, unedited)
- [ ] Theme files wired (see TOKEN-MAPPING.md)
- [ ] Visual validation done (dark + light, key screens)
- [ ] Conformity check green (`node fds-migration/scripts/check-fds-conformity.mjs`)
- [ ] Env de test deployed and validated

## Phase 2 — Components (future, not started)

Not scoped yet. See fds-migration/AGENTS.md rule 5 — do not start component
migration under this phase without an explicit go-ahead. When it starts,
order by filigran-design-system `ROADMAP.json` `priority`; readiness for
this product is COMPONENT-MAPPING.md's "Product status" column.

### Planned: Navbar

- Status: **planned** — not started (no branch, no owner, no go-ahead yet;
  still bound by rule 5 above). No implementation happens in this pass.
- Coverage audit already done: `COMPONENT-MAPPING.md` (generated from the
  lib, do not hand-edit) already carries the row
  `| Navbar | todo | todo | — | — | — |` — lib status `todo`, this product's
  status `todo`, no MUI identifiers/occurrences resolved yet (distinct from
  the separate `Header` row — `AppBar`/`Toolbar`, 4 occurrences / 2 files —
  in the same audit).
  Cross-checked against filigran-design-system `ROADMAP.json` `components[]`
  (`name: "Navbar"`): `status: "todo"`, `figmaDesigned: true`,
  `figmaNodeId: null`, `priority: 24` (of 25 components — second-lowest).
  Notes there flag it as "composant structurel, peu de levier de
  réutilisation cross-produit attendu" — same `todo` status tracked
  identically for `opencti`, `openaev`, and `opengrc`.
