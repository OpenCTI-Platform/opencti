# Title & Label Taxonomy

This document is the **source of truth** for how commits, pull requests and issues
are titled and labeled in this repository. It is shared across all Filigran
repositories (FiligranHQ, OpenCTI-Platform, OpenAEV-Platform, XTM-One-Platform,
OpenGRC-Platform) so the whole ecosystem stays consistent.

The machine-readable companion — each shared label's exact name, color and
description — lives in [`.github/labels.yml`](labels.yml). Keep the two in sync
when adding or renaming a shared label.

## 1. Title convention (Conventional Commits)

Every commit, pull request and issue title follows the
[Conventional Commits 1.0.0](https://www.conventionalcommits.org/en/v1.0.0/)
specification, with a GitHub issue reference appended:

```
type(scope?)!?: description (#issue)
```

- `type` is one of: `feat`, `fix`, `chore`, `docs`, `style`, `refactor`, `perf`,
  `test`, `build`, `ci`, `revert`.
- `scope` is optional — a **lowercase** noun in parentheses naming the affected
  area, e.g. `feat(api):`, `fix(frontend):`, `docs(connectors):`. The scope
  **replaces** the old `[backend]` / `[frontend]` / `[component]` bracket
  prefixes, which are **discontinued**.
- `!` is optional and marks a breaking change (e.g. `feat(api)!: ...`), optionally
  with a `BREAKING CHANGE:` footer.
- `description` **starts with a lowercase letter** and has **no trailing period**.
  Preserve acronyms and proper nouns: `OpenCTI`, `OpenAEV`, `XTM One`, `OpenGRC`,
  `STIX`, `LLM`, `Docker`, `Redis`.
- `(#issue)` is a **required reference on pull request titles** (the PR title
  becomes the squash-merge commit, so the reference lands on `master`/`main`).
  Issue titles omit it (the issue *is* the reference).

Enforcement is preventive and lives at the organization (enterprise) level; the
[`FiligranHQ/filigran-ci-tools` `pr-title-check`](https://github.com/FiligranHQ/filigran-ci-tools/tree/main/actions/pr-title-check)
action validates the same format. **Renovate** pull requests are exempt.

**Examples**

```
feat(connectors): add CrowdStrike Falcon endpoint security integration (#1234)
fix(frontend): correct file context limit handling (#1235)
docs: update deployment guide (#1236)
chore(ci): migrate dependency management to uv (#1237)
feat(api)!: remove deprecated v1 endpoints (#1238)
```

## 2. Type label (issues only — one per issue)

The title `type` maps to a primary type label. **Primary type labels are applied
to issues only:**

| Title prefix | Type label      | Color  |
|--------------|-----------------|--------|
| `feat:`      | `feature`       | indigo |
| `fix:`       | `bug`           | red    |
| `docs:`      | `documentation` | blue   |

On issues, also set the GitHub **Type** field to match (`feat:` → `Feature`,
`fix:` → `Bug`, every other type → `Task`).

`chore:`, `style:`, `ci:`, `build:`, `perf:`, `refactor:`, `test:` and `revert:`
are valid types; they do not each require a dedicated label (use a repository
area/scope label where useful). `security` is a **label** (applied on top of the
type, e.g. a `fix:` that closes a vulnerability), not a title type.

> **Pull requests do NOT carry a primary type label.** A pull request's `type:`
> title prefix (and its linked issue) already convey the type, so `feature`,
> `bug` and `documentation` must **never** be added to a pull request — remove
> them if they appear.
>
> Pull requests **do** still carry other labels. In particular, add an
> **ownership** label — typically `filigran team` or `community` — so the source
> of a contribution is clear at a glance. Area/scope labels and workflow labels
> (e.g. `dependencies`, `do not merge`) also apply to pull requests where useful.

## 3. Workflow & ownership labels

- **Triage**: `needs triage`, `needs more info`, `solved`, `duplicate`,
  `wontfix`, `question`.
- **Severity / size**: `critical`, `epic`, `tiny`, `regression`,
  `breaking-change`.
- **Ownership**: `filigran team`, `community`, `community support`,
  `filigran support`, `partner support`, `enterprise edition`.
- **Security**: `security`.
- **CLA**: `cla:pending`, `cla:signed`, `cla:exempt`.
- **Automation**: `dependencies`, `javascript`, `python`, `java`, `do not merge`.

See [`.github/labels.yml`](labels.yml) for the exact colors and descriptions.

## 4. Area / scope labels (optional, may have several)

On top of the shared labels above, repositories define their own area/scope
labels (e.g. `frontend`, `backend`, `connector: <name>`, `collector: <name>`,
`agents`, `authentication`). They add routing context and an issue may carry
more than one. They are not listed in `labels.yml`.

All label names are **lowercase**. Repository-specific labels use a neutral grey
color (`ededed`); only the shared labels above carry color, so the common
taxonomy stands out consistently across every Filigran repository.

## 5. Deprecated labels — do not use

- `enhancement` — use `feature`.
- `feature request` / `feature-request` — use `feature` (+ `needs triage`).
- `improvement` / `nice-to-have` — use `feature` + area labels.

## 6. Quick checklist for a new issue / PR

- [ ] Title follows `type(scope?)!?: description` (lowercase, no trailing period)
- [ ] Pull request titles end with the `(#issue)` reference
- [ ] **Issues only:** exactly one primary type label (`feature` / `bug` /
      `documentation`) matches the title prefix, and the GitHub **Type** field
      (Feature / Bug / Task) is set to match
- [ ] **Pull requests:** no primary type label (the title prefix conveys the
      type); add an ownership label (`filigran team` / `community`) and any useful
      area labels
- [ ] Area labels added where useful
- [ ] No deprecated labels
- [ ] Commits are signed and the PR is linked to an issue
