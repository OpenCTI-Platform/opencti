// Message templates for ingestion health checks.
//
// One table, two renderers:
//  - the server renders English here, for notifiers and API clients (there is
//    no server-side i18n, and `activityListener` already builds English
//    messages the same way);
//  - the front end renders the same template through
//    `t_i18n(template, { id, values: params })`, so the UI follows the user's
//    locale.
//
// OpenCTI's i18n convention uses the English text as the message id, so this
// table doubles as the key source for `lang/*.json`. Keep the two in sync by
// never writing a health sentence anywhere else.

export const CHECK_MESSAGE_TEMPLATES = {
  // liveness
  NO_HEARTBEAT: 'No ping received since {last_seen}',
  NO_CONSUMER: 'Queue has had no consumer since {idle_since}',
  MANUALLY_STOPPED: 'Stopped by a user {since}',
  // productivity
  NEVER_RUN: 'Registered {since} but has never run',
  RUN_OVERDUE: 'Expected to run {expected_at}, no run since {last_run_at}',
  // Used when the source declares no schedule: there is no "expected at" to
  // quote, and quoting `last_run_at` twice reads as a bug.
  RUN_STALE: 'No run since {last_run_at}',
  LAST_RUN_ERROR: 'Last run failed: {error}',
  EMPTY_RUNS: 'Ran {count} times without importing any object',
  CURSOR_STALLED: 'Polling successfully but the cursor has not moved since {since}',
} as const;

export type IngestionCheckCode = keyof typeof CHECK_MESSAGE_TEMPLATES;

// Connector error strings are untrusted input: they can be long and they
// routinely carry credentials in URLs. Truncate and redact before a template
// slot puts them in an email.
const MAX_DETAIL_LENGTH = 500;
const SECRET_PATTERNS: RegExp[] = [
  /([?&](?:token|key|api_?key|apikey|password|secret|access_?token)=)[^&\s]+/gi,
  /(Bearer\s+)[A-Za-z0-9._~+/-]+=*/gi,
  /(:\/\/[^:/\s]+:)[^@\s]+(@)/g, // basic-auth credentials in a URL
];

export const sanitizeCheckDetail = (raw: string | undefined | null): string | undefined => {
  if (!raw) {
    return undefined;
  }
  let value = String(raw);
  SECRET_PATTERNS.forEach((pattern) => {
    value = value.replace(pattern, (...args) => {
      // Keep the capture groups that identify the field, drop the value.
      const groups = args.slice(1, -2).filter((g) => typeof g === 'string');
      return `${groups.join('')}[redacted]`;
    });
  });
  value = value.replace(/\s+/g, ' ').trim();
  return value.length > MAX_DETAIL_LENGTH ? `${value.slice(0, MAX_DETAIL_LENGTH)}…` : value;
};

export type CheckParams = Record<string, string | number>;

// Renders a template by substituting {placeholders}. An absent param renders as
// "unknown" rather than leaving a raw brace in a user-visible sentence.
export const renderCheckMessage = (code: IngestionCheckCode, params: CheckParams = {}): string => {
  return CHECK_MESSAGE_TEMPLATES[code].replace(/\{(\w+)\}/g, (_, key: string) => {
    const value = params[key];
    return value === undefined || value === null || value === '' ? 'unknown' : String(value);
  });
};

// Status labels used to build the one-sentence summary. Kept here so the
// summary and the checks share a single vocabulary.
export const STATUS_LABELS: Record<string, string> = {
  healthy: 'Healthy',
  idle: 'Idle',
  degraded: 'Degraded',
  critical: 'Critical',
  stopped: 'Stopped',
  unknown: 'Unknown',
};

export const RECOVERY_MESSAGE = 'Recovered — back to normal after {duration}';
