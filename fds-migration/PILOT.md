# The pilot instance

Written because the night run of 2026-08-29 needed it and found it recorded
nowhere in this repository — the URL lived only in a shell script in one
person's home directory.

There are **two** things people call "the pilot". They are not the same and
they refresh differently.

## 1. The local pilot — what a reviewer actually opens

**<http://localhost:3000>** — front on 3000, backend on 4000.

Started by `~/demo-opencti.sh` (not in this repo: it is a personal script). It
brings up the docker infrastructure, then the GraphQL backend, then the front.
The login is `admin@opencti.io`; the password is in that script and is
deliberately **not** recorded here.

Two things to know before pointing it at a different checkout:

- The backend accepts **one origin**. Two fronts cannot both talk to it, so a
  second checkout has to take 3000 over rather than sit beside it on 3001.
- The script pins a specific worktree. Reading it before running it is quicker
  than debugging why your branch is not what you see.

## 2. The shared staging instance — what the branch deploys to

Redeployed by `.github/workflows/deploy-design-system.yml`, which fires **only
on a push to `design-system/current`** (plus `workflow_dispatch`). So it always
serves the branch tip, never an open pull request: a PR's work appears there
when it merges, not before.

The workflow restarts it through AWX with
`solution=opencti, customer=design-system, inventory=eu-west-staging`. Its URL
is not in the workflow and was not found anywhere in this repository —
**someone who knows it should add it here.** Until then, that is the identifier
to quote when asking for it.

Do not dispatch the workflow on an unmerged branch to preview something: it is
a shared instance, and it would replace what everyone else is looking at.
