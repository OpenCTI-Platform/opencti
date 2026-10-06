export type ManagerDomain = 'core' | 'knowledge' | 'ingestion' | 'notifications' | 'defense' | 'enterprise' | 'ecosystem' | 'other';

export type ManagerStatusFilter = 'all' | 'enabled' | 'disabled' | 'unlicensed';

// `unlicensed`: an Enterprise-only manager on a platform without the Enterprise Edition, off by design.
export type ManagerStatus = 'enabled' | 'disabled' | 'unlicensed';

export interface PlatformModule {
  readonly id: string;
  readonly enable: boolean;
}

export interface ManagerItem {
  id: string;
  label: string;
  status: ManagerStatus;
}

export interface ManagerGroup {
  domain: ManagerDomain;
  label: string;
  managers: ManagerItem[];
}

export interface ManagerCounts {
  all: number;
  enabled: number;
  disabled: number;
  unlicensed: number;
}

// Managers the backend only runs with an Enterprise Edition license.
export const ENTERPRISE_ONLY_MANAGERS = ['ACTIVITY_MANAGER', 'PLAYBOOK_MANAGER', 'FILE_INDEX_MANAGER', 'PIR_MANAGER'];

// Display order of the groups; the labels are translation keys.
export const MANAGER_DOMAINS: { domain: ManagerDomain; label: string }[] = [
  { domain: 'core', label: 'Core platform' },
  { domain: 'knowledge', label: 'Knowledge' },
  { domain: 'ingestion', label: 'Ingestion and connectors' },
  { domain: 'notifications', label: 'Notifications' },
  { domain: 'defense', label: 'Defense and investigations' },
  { domain: 'enterprise', label: 'Enterprise Edition' },
  { domain: 'ecosystem', label: 'Telemetry and Filigran ecosystem' },
  { domain: 'other', label: 'Other managers' },
];

const DOMAIN_BY_MANAGER: Record<string, ManagerDomain> = {
  RULE_ENGINE: 'core',
  HISTORY_MANAGER: 'core',
  TASK_MANAGER: 'core',
  EXPIRATION_SCHEDULER: 'core',
  GARBAGE_COLLECTION_MANAGER: 'core',
  RETENTION_MANAGER: 'core',
  EXCLUSION_LIST_CACHE_BUILD_MANAGER: 'core',
  EXCLUSION_LIST_CACHE_SYNC_MANAGER: 'core',
  WORKFLOW_STATUS_CLEANUP_MANAGER: 'core',
  DATA_SANITY_MANAGER: 'core',
  INDICATOR_DECAY_MANAGER: 'knowledge',
  KNOWLEDGE_FRESHNESS_MANAGER: 'knowledge',
  PROVENANCE_BACKFILL_MANAGER: 'knowledge',
  CURATION_MANAGER: 'knowledge',
  CURATION_RECORDS_MANAGER: 'knowledge',
  GRAPH_ANALYTICS_MANAGER: 'knowledge',
  SNAPSHOT_MANAGER: 'knowledge',
  TIMELINE_MANAGER: 'knowledge',
  PULSE_MANAGER: 'knowledge',
  CONNECTOR_MANAGER: 'ingestion',
  SYNC_MANAGER: 'ingestion',
  INGESTION_MANAGER: 'ingestion',
  CATALOG_MANAGER: 'ingestion',
  SOURCE_INTELLIGENCE_MANAGER: 'ingestion',
  NOTIFICATION_MANAGER: 'notifications',
  PUBLISHER_MANAGER: 'notifications',
  SUBSCRIPTION_MANAGER: 'notifications',
  DEFENSE_COVERAGE_MANAGER: 'defense',
  HUNT_MANAGER: 'defense',
  INDICATOR_DEPLOYMENT_MANAGER: 'defense',
  INVESTIGATION_RUN_MANAGER: 'defense',
  ACTIVITY_MANAGER: 'enterprise',
  PLAYBOOK_MANAGER: 'enterprise',
  FILE_INDEX_MANAGER: 'enterprise',
  PIR_MANAGER: 'enterprise',
  TELEMETRY_MANAGER: 'ecosystem',
  PLATFORM_USAGE_METRICS_MANAGER: 'ecosystem',
  HUB_REGISTRATION_MANAGER: 'ecosystem',
  XTM_ONE_REGISTRATION_MANAGER: 'ecosystem',
};

const ACRONYMS = new Set(['AI', 'API', 'CSV', 'EE', 'ID', 'IOC', 'PIR', 'SSO', 'STIX', 'TAXII', 'URL', 'XTM']);

// Product names whose casing a word-by-word pass cannot guess.
const PROPER_NOUNS: [RegExp, string][] = [
  [/\bXTM one\b/g, 'XTM One'],
  [/\bOpencti\b/gi, 'OpenCTI'],
  [/\bOpenaev\b/gi, 'OpenAEV'],
];

export const getManagerDomain = (id: string): ManagerDomain => DOMAIN_BY_MANAGER[id] ?? 'other';

/** `HUNT_MANAGER` -> "Hunt manager", `XTM_ONE_REGISTRATION_MANAGER` -> "XTM One registration manager". */
export const humanizeManagerId = (id: string): string => {
  const words = id.split(/[\s_-]+/).filter((word) => word.length > 0);
  if (words.length === 0) {
    return id;
  }
  const sentence = words
    .map((word, index) => {
      const upper = word.toUpperCase();
      if (ACRONYMS.has(upper)) {
        return upper;
      }
      const lower = word.toLowerCase();
      return index === 0 ? lower.charAt(0).toUpperCase() + lower.slice(1) : lower;
    })
    .join(' ');
  return PROPER_NOUNS.reduce((text, [pattern, replacement]) => text.replace(pattern, replacement), sentence);
};

/** The translated label when the key exists, the humanized id otherwise: a raw id never reaches the screen. */
export const getManagerLabel = (id: string, translate: (key: string) => string): string => {
  const translated = translate(id);
  return translated && translated !== id ? translated : humanizeManagerId(id);
};

/** `isEnterpriseEditionValid` is the validated license: the one the backend gates Enterprise-only managers on. */
export const getManagerStatus = (module: PlatformModule, isEnterpriseEditionValid: boolean): ManagerStatus => {
  if (ENTERPRISE_ONLY_MANAGERS.includes(module.id) && !isEnterpriseEditionValid) {
    return 'unlicensed';
  }
  return module.enable ? 'enabled' : 'disabled';
};

export const toManagerItems = (
  modules: ReadonlyArray<PlatformModule>,
  translate: (key: string) => string,
  isEnterpriseEditionValid: boolean,
): ManagerItem[] => modules.map((module) => ({
  id: module.id,
  label: getManagerLabel(module.id, translate),
  status: getManagerStatus(module, isEnterpriseEditionValid),
}));

export const countManagers = (managers: ManagerItem[]): ManagerCounts => {
  const count = (status: ManagerStatus) => managers.filter((manager) => manager.status === status).length;
  return { all: managers.length, enabled: count('enabled'), disabled: count('disabled'), unlicensed: count('unlicensed') };
};

const normalize = (value: string) => value.normalize('NFD').replace(/[\u0300-\u036f]/g, '').toLowerCase().trim();

/** Keeps the managers matching the status filter and whose label, humanized id or raw id contains every word of the search. */
export const filterManagers = (
  managers: ManagerItem[],
  status: ManagerStatusFilter,
  search: string,
): ManagerItem[] => {
  const terms = normalize(search).split(/\s+/).filter((term) => term.length > 0);
  return managers.filter((manager) => {
    if (status !== 'all' && manager.status !== status) return false;
    if (terms.length === 0) return true;
    const haystack = [manager.label, humanizeManagerId(manager.id), manager.id].map(normalize).join(' ');
    return terms.every((term) => haystack.includes(term));
  });
};

/** Groups in display order, managers sorted by label inside each group, empty groups dropped. */
export const groupManagers = (
  managers: ManagerItem[],
  translate: (key: string) => string,
): ManagerGroup[] => MANAGER_DOMAINS
  .map(({ domain, label }) => ({
    domain,
    label: translate(label),
    managers: managers
      .filter((manager) => getManagerDomain(manager.id) === domain)
      .sort((a, b) => a.label.localeCompare(b.label)),
  }))
  .filter((group) => group.managers.length > 0);
