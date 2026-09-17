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

Full machine-readable reference: <https://silver-doodle-mnyv84e.pages.github.io/llms-full.txt>
(same content as the sibling checkout's `filigran-design-system/llms-full.txt`,
served by the docs site).

## Non-negotiable rules

1. **Never hand-edit a generated file.** `opencti-platform/opencti-front/src/components/fds-tokens.generated.ts` and its sidecar
   `.meta.json` are produced by `pnpm generate:mui-bridge` in the
   filigran-design-system repo. If a value looks wrong, fix `theme.css`
   upstream (a Figma export, delivered by a human designer) — never patch
   the generated file here.
2. **Never invent a token value.** A color/spacing/typography value with no
   design-system equivalent is a gap to flag (TOKEN-MAPPING.md, section
   "Tokens to create in Figma"), not something to improvise.
3. **Branch discipline.** All work happens on `fds/*` branches, never on
   this product's main/master. Run `git branch --show-current` before
   every commit. No push to any remote without explicit human validation.
4. **Missing component → flag, never fork.** If a design-system component
   doesn't exist yet for something you're migrating, report the gap
   (filigran-design-system's `process/AI-BACKLOG.md` or `ROADMAP.json`)
   and move on — never build a local approximation.
5. **The component phase has started — declare every adoption.** Wiring
   token *values* into the product's MUI theme (IMPLEMENTATION-ROADMAP.md,
   "Phase 1") is no longer the only workstream: products now replace their
   own container/control components with design-system ones. What changed
   is not that anything goes — it is that adoptions must be **declared**,
   not merely written.

   Every adopted component gets an entry in `migration-state.json`'s
   `libComponentUsage`: the component name, `importFrom`, the exact list
   of files, the guards it runs under (`imported-from-library`,
   `no-hardcoded-padding`), and a `reason`. An adoption absent from that
   list is invisible to `check-fds-conformity.mjs` — it will not be caught
   when it silently reverts to MUI or when a hardcoded padding creeps back.

   **An agent may convert a component when all four hold:**
   1. the design-system component **exists** and the capability is verified
      on the **installed build** (`node_modules`), not on its types, its
      meta or the changelog;
   2. the visual delta has been **measured** and either is iso, or is a
      change a human explicitly asked for — never "close enough" chosen
      silently;
   3. the conversion loses **no** function, information or interaction —
      where it would, the site is listed with its reason instead of forced;
   4. the adoption is **declared** in `libComponentUsage` in the same
      change set as the code.

   If any of the four fails, stop and report the gap (this repo's
   `process/AI-BACKLOG.md`) rather than approximate it locally. Rule 4
   above still applies in full: a missing component is flagged, never
   forked.

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

### Declaring a component-adoption site (`libComponentUsage`)

Once a real design-system COMPONENT (not just its tokens) is adopted in a
file, declare it in `migration-state.json`'s `libComponentUsage` so the
check keeps watching it:

```jsonc
"libComponentUsage": [
  {
    "component": "Paper",
    "importFrom": "@filigran/design-system",
    "files": ["opencti-front/src/.../PanelWidget.tsx"],
    "guards": ["imported-from-library", "no-hardcoded-padding"],
    "reason": "Paper owns padding as a typed prop (0|8|16|24|32) since the Phase 0 round"
  }
]
```

Two things to know before writing one:

- **You declare intent, never a pattern.** `guards` names checks the design
  system implements and maintains; an unknown name is reported `INVALID`
  rather than passing quietly, so a typo can never read as coverage. Run
  the check with an obviously wrong name once if you want to see the list.
- **The scan is structural, not textual.** Each `<Component …>` opening tag
  is walked to its own closing `>` with quotes, template literals and `{}`
  nesting tracked, after comments are stripped — so a multiline element is
  the normal case, a padding on a sibling element is not attributed to this
  one, and a commented-out class cannot produce a finding. Findings name one
  element and one line.

Available guards today:

| Guard | What it catches |
|---|---|
| `imported-from-library` | the component is rendered but no longer imported from the library, or has fallen back to `@mui/material` — a revert the JSX alone cannot show |
| `no-hardcoded-padding` | a rendered instance sets padding through `className`, `sx` or `style` instead of the component's own `padding` prop, re-forking a scale the component now owns |

## Notes

MUI 6.5 + @mui/styles legacy. Theme files: src/components/ThemeDark.ts / ThemeLight.ts.
