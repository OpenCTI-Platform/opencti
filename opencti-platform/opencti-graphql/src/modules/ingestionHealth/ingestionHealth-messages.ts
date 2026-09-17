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
  // stability — composer-supervised connectors only
  REBOOT_LOOP: 'Restarted {count} times in the last {window}',
} as const;

// Configuration findings are a separate axis, not another rung on the runtime
// ladder: a source running under a personal account ingests perfectly well, it
// is simply wrong. Keeping the two apart is what stops one masking the other.
export const CONFIGURATION_MESSAGE_TEMPLATES = {
  USER_NOT_SERVICE_ACCOUNT: 'Ingesting as {user}, which is a personal account rather than a service account',
  USER_MISSING: 'No user is configured to create data',
  USER_DISABLED: 'The configured user {user} is disabled',
  USER_MISSING_CAPABILITY: 'The configured user {user} lacks the {capability} capability',
  TOKEN_EXPIRED: 'The configured token expired {since}',
  TOKEN_EXPIRING: 'The configured token expires {expires_at}',
  EMPTY_SCOPE: 'No scope configured',
  CONFIDENCE_UNSET: 'No confidence level is set for the ingesting user',
  CONTRACT_CONFIG_INCOMPLETE: 'Required configuration fields are not set: {fields}',
  VERSION_MISMATCH: 'Image {image} is not compatible with this platform version',
  DUPLICATE_QUEUE: 'Another source is already using this queue',
} as const;

export const ALL_MESSAGE_TEMPLATES = {
  ...CHECK_MESSAGE_TEMPLATES,
  ...CONFIGURATION_MESSAGE_TEMPLATES,
} as const;

export type IngestionRuntimeCheckCode = keyof typeof CHECK_MESSAGE_TEMPLATES;
export type IngestionConfigurationCheckCode = keyof typeof CONFIGURATION_MESSAGE_TEMPLATES;
export type IngestionCheckCode = keyof typeof ALL_MESSAGE_TEMPLATES;

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
  return ALL_MESSAGE_TEMPLATES[code].replace(/\{(\w+)\}/g, (_, key: string) => {
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

export const CONFIGURATION_STATUS_LABELS: Record<string, string> = {
  ok: 'Configuration OK',
  advisory: 'Misconfigured',
  blocking: 'Cannot run as configured',
};

export const RECOVERY_MESSAGE = 'Recovered — back to normal after {duration}';
