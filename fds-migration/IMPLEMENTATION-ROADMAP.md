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

- Status: **planned** — not started for this product (no branch, no owner,
  no go-ahead yet for opencti adoption; still bound by rule 5 above). No
  implementation happens in this pass.
- Coverage audit: `COMPONENT-MAPPING.md` (generated from the lib, do not
  hand-edit) carries the row `| Navbar | done | todo | — | — | — |` — lib
  status **done**, this product's status still `todo` (opencti has not
  adopted it yet), no MUI identifiers/occurrences resolved yet (distinct
  from the separate `Header` row — `AppBar`/`Toolbar`, 4 occurrences / 2
  files — in the same audit).
  Cross-checked against filigran-design-system `ROADMAP.json` `components[]`
  (`name: "Navbar"`) and `Navbar.meta.ts`: `status: "done"`,
  `figmaDesigned: true`, `figmaNodeId: "2843:4074"`, `priority: 24` (of 25
  components — second-lowest). Implemented and merged via PR #43
  ("feat(navbar): Navbar, NavbarItem, NavbarSubmenu, ProductSwitcher",
  merged 2026-07-24); Navbar is a composition root, its sub-components
  (NavbarItem, NavbarSubmenu, ProductSwitcher) are tracked as their own
  `ROADMAP.json` entries. Notes there flag it as "structural component, low
  cross-product reuse leverage expected" — product-level adoption is still
  `todo` identically for `opencti`, `openaev`, and `opengrc`.
