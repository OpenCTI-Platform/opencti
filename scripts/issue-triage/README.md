# Issue triage POC

Can a decision model triage our GitHub issues? This POC asks one three
questions about an issue and measures the answers against what maintainers
actually did:

| Decision | Answer | Ground truth |
|---|---|---|
| Type | `bug`, `feature`, `documentation` or `question` | The type label on the issue |
| Area | One of the area labels in `src/taxonomy.ts`, or `none` | The area label on the issue |
| Needs more info | A probability | Not scored (see limits) |

It is a skeleton: the plumbing is tested, **no real model has been run through
it yet**, so there is no accuracy number to quote.

## Providers

The model sits behind one interface (`Classifier` in `src/classifier.ts`), with
two implementations selected by the environment:

| Provider | Selected when | Configuration |
|---|---|---|
| `jev` — [Jev](https://docs.typesafe.ai/), TypeSafe AI's decision model | `TYPESAFE_API_KEY` is set | `TRIAGE_MODEL` pins a release, e.g. `jev-1.13.0` (default `jev-latest`, which moves) |
| `llm` — any OpenAI-compatible chat API, e.g. an open-source model served by Ollama or vLLM | `LLM_MODEL` is set | `LLM_BASE_URL` (default `http://localhost:11434/v1`, Ollama), `LLM_API_KEY` if the API needs one |

`TRIAGE_PROVIDER=jev|llm` forces the choice when both are configured.

The `llm` provider is both the way to run the POC without a Jev subscription
and the baseline Jev has to beat: "a general LLM constrained to JSON does this
already" is the first objection to expect. One difference matters when reading
the reports: Jev returns a probability per label, whereas the `llm` confidence
is the model's own estimate of itself, so its threshold table deserves less
trust.

## Run it

Node 22.18 or later runs the TypeScript sources directly; there is no build.

```bash
cd scripts/issue-triage && npm ci
```

Evaluate on the 200 most recent closed issues with an open-source model served
by Ollama (replace the model name with one you have pulled):

```bash
LLM_MODEL=<model> GITHUB_TOKEN=<token> npm run evaluate -- --limit 200
```

The same with Jev:

```bash
TYPESAFE_API_KEY=<key> TRIAGE_MODEL=jev-1.13.0 GITHUB_TOKEN=<token> npm run evaluate -- --limit 200
```

`GITHUB_TOKEN` is optional on a public repository but the anonymous rate limit
is low. `--input issues.json` replays a saved `Issue[]` instead of calling
GitHub, which keeps two providers on exactly the same issues. The report lands
in `out/report.md`, the raw predictions in `out/predictions.json`.

```bash
npm test
```

```bash
npm run typecheck
```

## Reading the report

- **Accuracy vs. the majority baseline.** Always answering `bug` is right most
  of the time here; a model is only useful by the margin above that line.
- **The threshold table** is the product decision: at which confidence could
  labels be applied automatically, how many issues would that cover, and how
  often would it be wrong.
- **Most frequent mistakes** usually point at two labels whose descriptions
  overlap in `src/taxonomy.ts`. Fix the description, rerun.

## Shadow workflow

`.github/workflows/issue-triage-shadow.yml` runs the triage on every new issue
and writes the suggestion to the job summary. It applies no label and posts no
comment; its token is read-only. It does nothing until a provider is
configured (secret `TYPESAFE_API_KEY`, or variable `LLM_MODEL` plus
`LLM_BASE_URL` and secret `LLM_API_KEY`). Run manually, it triages one given
issue or runs the evaluation and uploads the report as an artifact.

`TRIAGE_POST_COMMENT=true` makes the script comment the suggestion on the
issue. The workflow does not set it and would need `issues: write` first.

## Limits to state when presenting

- **The type is easy by construction.** Issue templates apply the type label
  and impose a `fix(scope):` title. The title prefix is stripped before the
  model sees it (`--keep-title-prefix` to compare), but template headings
  remain in the body. The area is the more honest test.
- **Area labels are sparse.** Most issues carry none, and those are left out
  of the area score rather than counted as `none`. The area list is seeded
  from recently closed issues and needs a pass by the product team.
- **Human labels are not always right**, and some issues carry none: expect a
  ceiling below 100%.
- **`needs more info` is not scored**: the label is removed once the author
  answers, so closed issues no longer carry it. It is shown in shadow mode only.
- **Duplicate detection is out of scope**: it needs retrieval over past issues
  before any decision can be made.
- **An issue is untrusted text** that can try to steer its own classification.
  Harmless in shadow mode; a reason to keep a human in the loop below a high
  confidence threshold if labels are ever applied.
- **Issue content leaves GitHub** for the provider's API. Issues of this
  repository are public; reconsider before pointing this at a private one.
