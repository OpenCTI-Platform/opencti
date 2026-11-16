/**
 * The decision space handed to Jev. Keys are the exact GitHub label names, so a
 * decision maps to a label without a lookup table; values are the descriptions
 * the model reads to tell the labels apart.
 */

/** Primary type labels, from .github/labels.yml. */
export const TYPE_CRITERIA = {
  bug: 'Something that used to work or is documented to work does not: a crash, an error, a wrong result or a regression.',
  feature: 'A request for a new capability or an improvement to an existing one, including technical improvements.',
  documentation: 'Only the documentation is missing, wrong or unclear; no change to the product behavior is requested.',
  question: 'The author asks how to use, configure or understand the product and reports no defect.',
} as const;

/**
 * Area labels. They are repository-specific and absent from labels.yml: this
 * list is seeded from the labels seen on recently closed issues and has to be
 * completed with the product team before the numbers mean anything.
 * `none` is the escape hatch that keeps the model from forcing a wrong area.
 */
export const AREA_CRITERIA = {
  dashboards: 'Custom and public dashboards, widgets and their data.',
  export: 'Exporting data out of the platform: STIX, CSV, TXT or PDF exports and export connectors.',
  ingestion: 'Bringing data in: RSS, TAXII, CSV and JSON feeds, mappers, connectors and the worker.',
  'form intake': 'Intake forms used to create entities.',
  'client-python': 'The pycti Python client library.',
  authentication: 'Login, logout, sessions, SSO providers and redirects.',
  rbac: 'Access rights on data: capabilities, sharing, markings and view or edit restrictions.',
  iam: 'Managing users, service accounts, groups, roles and organizations.',
  notifications: 'Triggers, digests and notifiers such as email or webhooks.',
  activity: 'Audit and activity logs.',
  performance: 'Slowness, memory or scalability of queries, the engine or the cache.',
  ui: 'Display, layout or interaction problems of the web interface that fit no area above.',
  'content-editor': 'The rich text and markdown editors.',
  'security posture': 'Hardening of the platform itself: secrets handling, redaction, outbound request controls.',
  none: 'No area above clearly applies.',
} as const;

export type TypeLabel = keyof typeof TYPE_CRITERIA;
export type AreaLabel = keyof typeof AREA_CRITERIA;

export const TYPE_LABELS = Object.keys(TYPE_CRITERIA) as TypeLabel[];
/** Area labels that exist on GitHub, i.e. without the `none` escape hatch. */
export const AREA_LABELS = (Object.keys(AREA_CRITERIA) as AreaLabel[]).filter((label) => label !== 'none');
