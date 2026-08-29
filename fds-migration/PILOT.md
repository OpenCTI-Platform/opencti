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

## 3. The stacked preview — built from an unmerged stack, for a visual pass

Not a permanent instance: a static server for the built front, put up so the
complete state can be SEEN before anything merges. Recreate it with

```
cd opencti-platform/opencti-front && yarn build
node <scratch>/serve-stack.mjs <path>/opencti-front/dist 3000 <backend-port>
```

**<http://localhost:3000>**

Two things it has to do that a plain static server does not:

- **Substitute the index.html placeholders.** The built `index.html` ships
  `%APP_TITLE%`, `%BASE_PATH%`, `%APP_FAVICON%`, `%APP_DESCRIPTION%` and
  `%APP_SCRIPT_SNIPPET%`; the BACKEND normally replaces them when it serves the
  front (`opencti-graphql/src/http/httpPlatform.js`). Serve the raw file and the
  app never boots — the same substitution has to happen in the server.
- **Proxy the API.** `/graphql`, `/auth`, `/stream`, `/storage`, `/logout`,
  `/schema`, `/taxii2`, `/feeds`, `/chatbot` and `/*/embedded/*` go to the
  backend. Port 3000 for the front is deliberate: the backend accepts one
  origin.

### Choosing the backend to proxy to — check the schema first

A front built from a branch will fail against a backend whose schema predates
it, and it fails on the screens rather than at build time. Compare before
picking:

```
diff <backend-worktree>/opencti-graphql/config/schema/opencti.graphql \
     ./opencti-platform/opencti-graphql/config/schema/opencti.graphql
```

Measured 2026-08-29 while putting this up: the backend on **:4000** differs by
11 lines — `x_opencti_score` is missing from `Malware`, `IntrusionSet` and
`ThreatActorGroup`, which the front queries in 33 generated artifacts and which
is itself one of the stepper fields on `ThreatActorGroupCreation`. Those three
entity families would have failed. The backends on **:4030** and **:4011**
matched exactly (0 differing lines), so the preview proxies :4030.

Credentials are per backend and are not recorded here — this repository is
public. The local demo instance's login lives in `~/demo-opencti.sh`.
