# AGENTS.md — fds-migration (OpenCTI)

GENERATED — do not edit by hand. Regenerate: `pnpm generate:fds-migration --product opencti --write-to-product` (filigran-design-system repo).

This file is the agent contract for the Filigran Design System migration
work in this repo. Read it before touching anything under `fds-migration/`
or any file listed in `migration-state.json`'s `wiredFiles`.

## Source of truth

Tokens, components and their docs live in a separate repo:
`@filigran/design-system` — the sibling `filigran-design-system/` checkout
in the Filigran workspace. This repo NEVER defines a design-system token
locally: every color, spacing, radius and typography value used here traces
back to `filigran-design-system/packages/filigran-design-system/src/tokens/theme.css`.

Full machine-readable reference: not yet published — the docs site isn't
deployed yet (as of 2026-07). Until it is, read
`filigran-design-system/llms-full.txt` directly from the sibling checkout.

## Non-negotiable rules

1. **Never hand-edit a generated file.** `opencti-platform/opencti-front/src/components/fds-tokens.generated.ts` and its sidecar
   `.meta.json` are produced by `pnpm generate:mui-bridge` in the
   filigran-design-system repo. If a value looks wrong, fix `theme.css`
   upstream (a Figma export, delivered by a human designer) — never patch
   the generated file here.
2. **Never invent a token value.** A color/spacing/typography value with no
   design-system equivalent is a gap to flag (TOKEN-MAPPING.md, section
   "Tokens à créer dans Figma"), not something to improvise.
3. **Branch discipline.** All work happens on `fds/*` branches, never on
   this product's main/master. Run `git branch --show-current` before
   every commit. No push to any remote without explicit human validation.
4. **Missing component → flag, never fork.** If a design-system component
   doesn't exist yet for something you're migrating, report the gap
   (filigran-design-system's `process/AI-BACKLOG.md` or `ROADMAP.json`)
   and move on — never build a local approximation.
5. **This phase is TOKENS ONLY.** The current chantier
   (IMPLEMENTATION-ROADMAP.md, "Phase 1") wires design-system token
   *values* into this product's existing MUI theme — it does not touch
   component code. Migrating individual components to design-system
   components is a separate, future process with its own prompt; do not
   start it here unless explicitly asked.

## Where things are

| What | Where |
|---|---|
| Generated token data | `opencti-platform/opencti-front/src/components/fds-tokens.generated.ts` (+ `.meta.json` sidecar) |
| Token → theme-field wiring decisions | `fds-migration/TOKEN-MAPPING.md` |
| What to migrate, in what order, current state | `fds-migration/IMPLEMENTATION-ROADMAP.md` |
| Session journal (append, never rewrite) | `fds-migration/IMPLEMENTATION-LOG.md` |
| MUI component → design-system component reference | `fds-migration/COMPONENT-MAPPING.md` |
| Conformity check (run before every commit touching a wired file) | `node fds-migration/scripts/check-fds-conformity.mjs` |
| Upstream state manifest | `filigran-design-system/ROADMAP.json` (`implementations`, id `tokens-opencti`) |

## Conformity check

Run `node fds-migration/scripts/check-fds-conformity.mjs` before committing
any change to a file listed in `migration-state.json`'s `wiredFiles`. It
verifies the generated bridge file hasn't been hand-edited, that wired
files still import it, and that no hardcoded value has crept back into a
migrated zone. Fix everything it reports before committing — it lists
concrete file:line issues, it does not need re-deriving by hand.

## Notes

MUI 6.5 + @mui/styles legacy. Theme files: src/components/ThemeDark.ts / ThemeLight.ts.
