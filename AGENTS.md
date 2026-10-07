# AGENTS.md — OpenCTI

Repository conventions live in `.github/copilot-instructions.md` and
`.github/instructions/`. This file covers one thing they do not: the Filigran
Design System, which is migrating into this product.

`CLAUDE.md` is a one-line import of this file.

## The priority rule

> If the design system ships the component, using it is mandatory.
> If the design system does not ship it yet, MUI is the fallback, and the gap
> must be recorded.

This paragraph is a copy. The single source is `AGENTS.md` §4 in
[filigran-design-system](https://github.com/XTM-Foundation/filigran-design-system);
if the two ever disagree, that one wins.

Which components are already in service **here** is data, not memory:

```bash
node fds-migration/scripts/check-mui-regression.mjs --explain
```

It prints what is enforced, what is held while the library settles its API, and
what has no MUI counterpart at all. Record a gap in
`fds-migration/LIBRARY-FEEDBACK.md`.

## Onboarding — first session in this repo

1. Read this file, then `.github/copilot-instructions.md`.
2. Touching the front end? Run `--explain` above before writing UI code.
3. Read `fds-migration/AGENTS.md` before changing anything under
   `fds-migration/` or any file listed in `migration-state.json`'s `wiredFiles`.

What will stop you:

| Gate | Fires when |
|---|---|
| `check-mui-regression.mjs` | New code imports a MUI component the design system already replaces here |
| `check-fds-conformity.mjs` | A generated bridge file was hand-edited, went stale, or a hardcoded value returned to a migrated zone |

Both run in CI on every pull request and go red on a violation. Run them
locally first — they name file and line, and never need re-deriving by hand.
Whether a red one also *prevents* the merge depends on the repository's
required-check settings, which are an administrator's to set.

Never hand-edit a file carrying a `GENERATED` header: fix the source in the
design system repo and regenerate.
