# Logging Levels

`logApp` (`src/config/conf.js`) exposes four levels: `debug`, `info`, `warn`, `error`.
`logAudit` is a separate stream with its own retention and audience — it is not a
severity, and application events never go there.

Choosing between them is a judgement call, not a style preference: `ERROR` is the
level someone alerts on, and every inaccurate `ERROR` makes the real ones less
likely to be seen. Over-using `ERROR` and under-using `WARN` is by far the most
common mistake in this codebase — expect review pushback in that direction.

## The two rules that decide the level

1. **The pager test.** Would this record justify waking someone at 3 a.m.?
   Yes → `error`. No → `warn` or below. **If nobody can act on it, it is not an error.**
2. **A user error is not an application error.** A malformed feed, a rejected
   webhook, an invalid STIX bundle, a legacy task record, a user-configured SMTP
   server that refuses: the platform behaved correctly and rejected bad input or
   reported a remote failure. That is `warn` or `info`.

## Levels

| Level | Meaning | Typical use |
|---|---|---|
| `error` | An operation failed **and someone can act on it**. Work is lost or a platform function is down. | A manager's run died; an event batch was dropped; a write the platform depends on will not land. |
| `warn` | Degraded but recovered, or a problem building up. | Retry scheduled, fallback taken, one item skipped in a batch, external dependency unreachable, deprecated path used. |
| `info` | Notable business events and lifecycle transitions. **Production default.** | Manager started/stopped, feed execution started, N elements processed. |
| `debug` | Diagnostic detail, enabled on demand. | Per-element traces, timings, state transitions nobody reads in production. |

## Decision procedure

Ask these in order. The first "no" that applies usually settles it.

1. **Who acts on it, and what do they do?** No answer → not an `error`.
2. **Is the work lost?** An event dropped with no retry and no trace is
   actionable. One item skipped in a batch that runs again in 60 seconds is not.
3. **Is the outcome already surfaced?** Ingestion feeds, data sanity operations,
   playbook steps and background tasks persist their failure in the database and
   show it in the UI. The log record is then a second copy for someone who has a
   better source — `warn`.
4. **Whose fault is it?** Remote endpoint, user configuration, user-supplied
   data → `warn`. The platform's own storage, queue or invariants → `error`.
5. **Can it repeat unboundedly?** An `error` inside a retry loop or a per-item
   loop can emit millions of identical records during an incident, filling disks
   at the exact moment logs are needed. Log the aggregate, not the item.

## Recurring patterns

These six cover almost every logging site in `src/manager/**`, and the same
shapes appear across the backend.

| Pattern | Level | Why |
|---|---|---|
| Top-level handler catch (`if (e.name === TYPE_LOCK_ERROR) debug else …`) | `error` | The whole run failed; a platform function is down until the next tick. |
| Stream / event-batch catch, outside the item loop | `error` | The batch is dropped. If the stream state is advanced afterwards, the events are gone for good. |
| Per-item catch inside a loop that continues | `warn` + one aggregate record | One item is not a page. Report `errors_count` / `total_count` once at the end. |
| User-configured or external dependency failed (notifier, feed, remote API) | `warn` | Rule 2. Retried on the next cycle. |
| Degraded but recovered — fallback taken, retry scheduled, oversized payload skipped | `warn` | This is the definition of `warn`. If the message says "skipping" or "retrying", the level is wrong. |
| Failure to *record* a failure (push a UI log line, write a non-critical status) | `warn` | The primary failure is already logged and already user-visible. |

One exception worth naming, because it looks like the last row but is not: a
failed write to Elasticsearch that the platform's own logic then reads back
(an ingestion's `last_execution_status`, a manager's saved state) is a database
failure surfacing at the call site. That stays `error`.

## Things that do not change the level

- The word "error" appearing in the message or in a caught exception's name.
- A `catch` block existing at all.
- The code path feeling important.
- Wanting the record to be easy to find — that is what `event.name` and
  structured metadata are for, not severity inflation.

## Also worth getting right at the call site

Not severity, but cheap to fix while editing the same line:

- Pass the exception as `cause` — the codebase is otherwise consistent on this.
  `{ error: e.message }` throws away the stack.
- Include the identifier of whatever failed (`id`, `workId`, `taskId`, feed name).
  A record nobody can act on because it names nothing is not useful at any level.
- **Never log intelligence content**: STIX bundles, observable values, indicator
  patterns, analysis bodies, attachment content, or a resolved connector/step
  configuration (which can carry tokens). Log identifiers and counts.