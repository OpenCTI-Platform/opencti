import { describe, expect, it } from 'vitest';
import {
  countManagers,
  filterManagers,
  getManagerDomain,
  getManagerLabel,
  getManagerStatus,
  groupManagers,
  humanizeManagerId,
  ManagerItem,
  ManagerStatus,
  MANAGER_DOMAINS,
  toManagerItems,
} from './settingsManagersUtils';

const translations: Record<string, string> = {
  PLAYBOOK_MANAGER: 'Playbook manager',
  GARBAGE_COLLECTION_MANAGER: 'Trash manager',
  'Core platform': 'Plateforme',
  'Enterprise Edition': 'Edition Entreprise',
};
// Same contract as react-intl without a default message: a missing key comes back as the key itself.
const translate = (key: string) => translations[key] ?? key;

const item = (id: string, status: ManagerStatus = 'enabled'): ManagerItem => ({
  id,
  label: getManagerLabel(id, translate),
  status,
});

describe('humanizeManagerId', () => {
  it('turns an upper snake case id into a sentence', () => {
    expect(humanizeManagerId('HUNT_MANAGER')).toBe('Hunt manager');
    expect(humanizeManagerId('RULE_ENGINE')).toBe('Rule engine');
    expect(humanizeManagerId('EXCLUSION_LIST_CACHE_BUILD_MANAGER')).toBe('Exclusion list cache build manager');
  });

  it('keeps acronyms and product names', () => {
    expect(humanizeManagerId('PIR_MANAGER')).toBe('PIR manager');
    expect(humanizeManagerId('XTM_ONE_REGISTRATION_MANAGER')).toBe('XTM One registration manager');
    expect(humanizeManagerId('STIX_AI_MANAGER')).toBe('STIX AI manager');
  });

  it('accepts other separators and never returns an empty label', () => {
    expect(humanizeManagerId('data-sanity manager')).toBe('Data sanity manager');
    expect(humanizeManagerId('___')).toBe('___');
    expect(humanizeManagerId('')).toBe('');
  });
});

describe('getManagerLabel', () => {
  it('prefers the translation when the key exists', () => {
    expect(getManagerLabel('GARBAGE_COLLECTION_MANAGER', translate)).toBe('Trash manager');
  });

  it('falls back to the humanized id when the key is missing', () => {
    expect(getManagerLabel('CURATION_RECORDS_MANAGER', translate)).toBe('Curation records manager');
    expect(getManagerLabel('CURATION_RECORDS_MANAGER', () => '')).toBe('Curation records manager');
  });
});

describe('getManagerStatus', () => {
  it('tells a manager switched off by configuration from an Enterprise-only one without a valid license', () => {
    expect(getManagerStatus({ id: 'HUNT_MANAGER', enable: true }, false)).toBe('enabled');
    expect(getManagerStatus({ id: 'HUNT_MANAGER', enable: false }, false)).toBe('disabled');
    expect(getManagerStatus({ id: 'PLAYBOOK_MANAGER', enable: false }, false)).toBe('unlicensed');
    expect(getManagerStatus({ id: 'PIR_MANAGER', enable: false }, false)).toBe('unlicensed');
    expect(getManagerStatus({ id: 'PLAYBOOK_MANAGER', enable: false }, true)).toBe('disabled');
    expect(getManagerStatus({ id: 'PLAYBOOK_MANAGER', enable: true }, true)).toBe('enabled');
  });

  it('never shows an Enterprise-only manager as enabled without a valid license', () => {
    // The activity listener reports ACTIVITY_MANAGER as enabled whatever the license.
    expect(getManagerStatus({ id: 'ACTIVITY_MANAGER', enable: true }, false)).toBe('unlicensed');
    expect(getManagerStatus({ id: 'FILE_INDEX_MANAGER', enable: true }, false)).toBe('unlicensed');
  });
});

describe('toManagerItems and countManagers', () => {
  it('maps the platform modules and counts them by status', () => {
    const managers = toManagerItems([
      { id: 'PLAYBOOK_MANAGER', enable: false },
      { id: 'HUNT_MANAGER', enable: false },
      { id: 'RULE_ENGINE', enable: true },
    ], translate, false);
    expect(managers).toEqual([
      { id: 'PLAYBOOK_MANAGER', label: 'Playbook manager', status: 'unlicensed' },
      { id: 'HUNT_MANAGER', label: 'Hunt manager', status: 'disabled' },
      { id: 'RULE_ENGINE', label: 'Rule engine', status: 'enabled' },
    ]);
    expect(countManagers(managers)).toEqual({ all: 3, enabled: 1, disabled: 1, unlicensed: 1 });
    expect(countManagers([])).toEqual({ all: 0, enabled: 0, disabled: 0, unlicensed: 0 });
  });
});

describe('filterManagers', () => {
  const managers = [
    item('PLAYBOOK_MANAGER', 'unlicensed'),
    item('HUNT_MANAGER', 'disabled'),
    item('GARBAGE_COLLECTION_MANAGER'),
    item('RULE_ENGINE', 'disabled'),
  ];
  const ids = (list: ManagerItem[]) => list.map((manager) => manager.id);

  it('filters by status, an unlicensed manager under all and its own status only', () => {
    expect(ids(filterManagers(managers, 'all', ''))).toEqual(['PLAYBOOK_MANAGER', 'HUNT_MANAGER', 'GARBAGE_COLLECTION_MANAGER', 'RULE_ENGINE']);
    expect(ids(filterManagers(managers, 'enabled', ''))).toEqual(['GARBAGE_COLLECTION_MANAGER']);
    expect(ids(filterManagers(managers, 'disabled', ''))).toEqual(['HUNT_MANAGER', 'RULE_ENGINE']);
    expect(ids(filterManagers(managers, 'unlicensed', ''))).toEqual(['PLAYBOOK_MANAGER']);
  });

  it('searches the label and the humanized id, case and accent insensitive, every word', () => {
    expect(ids(filterManagers(managers, 'all', 'TRASH'))).toEqual(['GARBAGE_COLLECTION_MANAGER']);
    expect(ids(filterManagers(managers, 'all', 'garbage collection'))).toEqual(['GARBAGE_COLLECTION_MANAGER']);
    expect(ids(filterManagers(managers, 'all', '  hunt  '))).toEqual(['HUNT_MANAGER']);
    expect(ids(filterManagers(managers, 'all', 'hunt engine'))).toEqual([]);
    expect(ids(filterManagers([item('PULSE_MANAGER')], 'all', 'pulsé'))).toEqual(['PULSE_MANAGER']);
  });

  it('finds a manager by its raw id, whole or partial', () => {
    expect(ids(filterManagers(managers, 'all', 'GARBAGE_COLLECTION_MANAGER'))).toEqual(['GARBAGE_COLLECTION_MANAGER']);
    expect(ids(filterManagers(managers, 'all', 'rule_eng'))).toEqual(['RULE_ENGINE']);
  });

  it('combines the status filter and the search', () => {
    expect(ids(filterManagers(managers, 'enabled', 'hunt'))).toEqual([]);
    expect(ids(filterManagers(managers, 'disabled', 'engine'))).toEqual(['RULE_ENGINE']);
  });
});

describe('groupManagers', () => {
  it('groups by domain in display order, sorts by label and drops empty groups', () => {
    const groups = groupManagers([
      item('UNKNOWN_FUTURE_MANAGER'),
      item('RULE_ENGINE'),
      item('PLAYBOOK_MANAGER'),
      item('HISTORY_MANAGER'),
      item('PIR_MANAGER'),
    ], translate);
    expect(groups.map((group) => [group.domain, group.label, group.managers.map((manager) => manager.label)])).toEqual([
      ['core', 'Plateforme', ['History manager', 'Rule engine']],
      ['enterprise', 'Edition Entreprise', ['PIR manager', 'Playbook manager']],
      ['other', 'Other managers', ['Unknown future manager']],
    ]);
  });

  it('gives every manager registered by the platform a named group', () => {
    const registered = [
      'ACTIVITY_MANAGER', 'CATALOG_MANAGER', 'CONNECTOR_MANAGER', 'CURATION_MANAGER', 'CURATION_RECORDS_MANAGER',
      'DATA_SANITY_MANAGER', 'DEFENSE_COVERAGE_MANAGER', 'EXCLUSION_LIST_CACHE_BUILD_MANAGER',
      'EXCLUSION_LIST_CACHE_SYNC_MANAGER', 'EXPIRATION_SCHEDULER', 'FILE_INDEX_MANAGER', 'GARBAGE_COLLECTION_MANAGER',
      'GRAPH_ANALYTICS_MANAGER', 'HISTORY_MANAGER', 'HUB_REGISTRATION_MANAGER', 'HUNT_MANAGER', 'INDICATOR_DECAY_MANAGER',
      'INDICATOR_DEPLOYMENT_MANAGER', 'INGESTION_MANAGER', 'INVESTIGATION_RUN_MANAGER', 'KNOWLEDGE_FRESHNESS_MANAGER',
      'NOTIFICATION_MANAGER', 'PIR_MANAGER', 'PLATFORM_USAGE_METRICS_MANAGER', 'PLAYBOOK_MANAGER',
      'PROVENANCE_BACKFILL_MANAGER', 'PUBLISHER_MANAGER', 'PULSE_MANAGER', 'RETENTION_MANAGER', 'RULE_ENGINE',
      'SNAPSHOT_MANAGER', 'SOURCE_INTELLIGENCE_MANAGER', 'SUBSCRIPTION_MANAGER', 'SYNC_MANAGER', 'TASK_MANAGER',
      'TELEMETRY_MANAGER', 'TIMELINE_MANAGER', 'WORKFLOW_STATUS_CLEANUP_MANAGER', 'XTM_ONE_REGISTRATION_MANAGER',
    ];
    expect(registered.filter((id) => getManagerDomain(id) === 'other')).toEqual([]);
    expect(getManagerDomain('HUNT_MANAGER')).toBe('defense');
    expect(getManagerDomain('XTM_ONE_REGISTRATION_MANAGER')).toBe('ecosystem');
    expect(getManagerDomain('NOT_A_MANAGER')).toBe('other');
    expect(MANAGER_DOMAINS[MANAGER_DOMAINS.length - 1].domain).toBe('other');
  });
});
