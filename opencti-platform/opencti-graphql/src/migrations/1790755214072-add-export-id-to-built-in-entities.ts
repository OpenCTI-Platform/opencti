import * as R from 'ramda';
import { Promise as BluePromise } from 'bluebird';
import { logMigration } from '../config/conf';
import { BULK_TIMEOUT, elBulk, elList, ES_MAX_CONCURRENCY, MAX_BULK_OPERATIONS } from '../database/engine';
import { READ_INDEX_INTERNAL_OBJECTS, READ_INDEX_STIX_META_OBJECTS } from '../database/utils';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { generateBuiltInExportId } from '../schema/identifier';
import {
  ENTITY_TYPE_CAPABILITY,
  ENTITY_TYPE_GROUP,
  ENTITY_TYPE_RETENTION_RULE,
  ENTITY_TYPE_ROLE,
  ENTITY_TYPE_SETTINGS,
  ENTITY_TYPE_STATUS,
  ENTITY_TYPE_STATUS_TEMPLATE,
  ENTITY_TYPE_THEME,
} from '../schema/internalObject';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../schema/stixMetaObject';
import { ENTITY_TYPE_ENTITY_SETTING } from '../modules/entitySetting/entitySetting-types';
import { ENTITY_TYPE_MANAGER_CONFIGURATION } from '../modules/managerConfiguration/managerConfiguration-types';
import { ENTITY_TYPE_VOCABULARY } from '../modules/vocabulary/vocabulary-types';
import { ENTITY_TYPE_EMAIL_TEMPLATE } from '../modules/emailTemplate/emailTemplate-types';
import { ENTITY_TYPE_NOTIFIER } from '../modules/notifier/notifier-types';
import { ENTITY_TYPE_FINTEL_TEMPLATE } from '../modules/fintelTemplate/fintelTemplate-types';

const message = '[MIGRATION] Add export_id to built-in entities';

type NaturalKey = Record<string, string>;
type StoredElement = {
  _index: string;
  _id?: string;
  internal_id: string;
  entity_type: string;
  created_at?: string;
  export_id?: string;
  [key: string]: any;
};
type ExportIdAssignment = { element: StoredElement; export_id: string };

const BUILT_IN_VOCABULARIES: Record<string, string[]> = {
  account_type_ov: ['facebook', 'ldap', 'nis', 'openid', 'radius', 'skype', 'tacacs', 'twitter', 'unix', 'windows-local', 'windows-domain'],
  attack_resource_level_ov: ['individual', 'club', 'contest', 'team', 'organization', 'government'],
  attack_motivation_ov: [
    'accidental', 'coercion', 'dominance', 'ideology', 'notoriety', 'organizational-gain', 'personal-gain', 'personal-satisfaction', 'revenge',
    'unpredictable',
  ],
  coverage_ov: ['prevention', 'detection', 'vulnerability'],
  case_severity_ov: ['low', 'medium', 'high', 'critical'],
  case_priority_ov: ['P1', 'P2', 'P3', 'P4'],
  channel_types_ov: ['Twitter', 'Facebook'],
  event_type_ov: ['conference', 'financial', 'holiday', 'international-summit', 'local-election', 'national-election', 'sport-competition'],
  grouping_context_ov: ['suspicious-activity', 'malware-analysis', 'unspecified'],
  implementation_language_ov: [
    'applescript', 'bash', 'c', 'c++', 'c#', 'go', 'java', 'javascript', 'lua', 'objective-c', 'perl', 'php', 'powershell', 'python', 'ruby', 'rust',
    'scala', 'swift', 'typescript', 'visual-basic', 'x86-32', 'x86-64',
  ],
  incident_response_types_ov: ['ransomware', 'data-leak'],
  incident_type_ov: [
    'alert', 'compromise', 'information-system-disruption', 'ransomware', 'reputation-damage', 'data-leak', 'typosquatting', 'phishing',
    'cybercrime',
  ],
  incident_severity_ov: ['low', 'medium', 'high', 'critical'],
  indicator_type_ov: ['anomalous-activity', 'anonymization', 'benign', 'compromised', 'malicious-activity', 'attribution', 'unknown'],
  infrastructure_type_ov: [
    'amplification', 'anonymization', 'botnet', 'command-and-control', 'control-system', 'exfiltration', 'firewall', 'hosting-malware',
    'hosting-target-lists', 'phishing', 'reconnaissance', 'routers-switches', 'staging', 'workstation', 'unknown',
  ],
  integrity_level_ov: ['low', 'medium', 'high', 'system'],
  malware_capabilities_ov: [
    'accesses-remote-machines', 'anti-debugging', 'anti-disassembly', 'anti-emulation', 'anti-memory-forensics', 'anti-sandbox', 'anti-vm',
    'captures-input-peripherals', 'captures-output-peripherals', 'captures-system-state-data', 'cleans-traces-of-infection', 'commits-fraud',
    'communicates-with-c2', 'compromises-data-availability', 'compromises-data-integrity', 'compromises-system-availability',
    'controls-local-machine', 'degrades-security-software', 'degrades-system-updates', 'determines-c2-server', 'emails-spam', 'escalates-privileges',
    'evades-av', 'exfiltrates-data', 'fingerprints-host', 'hides-artifacts', 'hides-executing-code', 'infects-files', 'infects-remote-machines',
    'installs-other-components', 'persists-after-system-reboot', 'prevents-artifact-access', 'prevents-artifact-deletion',
    'probes-network-environment', 'self-modifies', 'steals-authentication-credentials', 'violates-system-operational-integrity',
  ],
  malware_result_ov: ['malicious', 'suspicious', 'benign', 'unknown'],
  malware_type_ov: [
    'adware', 'backdoor', 'bot', 'bootkit', 'ddos', 'downloader', 'dropper', 'exploit-kit', 'keylogger', 'ransomware', 'remote-access-trojan',
    'resource-exploitation', 'rogue-security-software', 'rootkit', 'screen-capture', 'spyware', 'trojan', 'unknown', 'virus', 'webshell', 'wiper',
    'worm',
  ],
  note_types_ov: ['internal', 'assessment', 'analysis', 'feedback', 'external'],
  opinion_ov: ['strongly-disagree', 'disagree', 'neutral', 'agree', 'strongly-agree'],
  organization_type_ov: ['constituent', 'csirt', 'partner', 'vendor', 'other'],
  permissions_ov: ['User', 'Administrator'],
  platforms_ov: ['android', 'macos', 'linux', 'windows'],
  collection_layers_ov: ['container', 'cloud-control-plane', 'host', 'OSINT', 'network'],
  pattern_type_ov: ['stix', 'pcre', 'sigma', 'snort', 'suricata', 'yara', 'tanium-signal', 'spl', 'eql', 'shodan', 'nova'],
  processor_architecture_ov: ['alpha', 'arm', 'ia-64', 'mips', 'powerpc', 'sparc', 'x86', 'x86-64'],
  persona_type_ov: ['true name', 'previous true name', 'nickname', 'moniker', 'assumed name', 'alternative spelling/transliteration', 'unknown'],
  reliability_ov: [
    'A - Completely reliable', 'B - Usually reliable', 'C - Fairly reliable', 'D - Not usually reliable', 'E - Unreliable',
    'F - Reliability cannot be judged',
  ],
  report_types_ov: ['threat-report', 'internal-report'],
  request_for_information_types_ov: ['none'],
  request_for_takedown_types_ov: ['phishing', 'brand-abuse'],
  security_platform_type_ov: ['EDR', 'XDR', 'SIEM', 'SOAR', 'NDR', 'ISPM'],
  service_status_ov: [
    'SERVICE_CONTINUE_PENDING', 'SERVICE_PAUSE_PENDING', 'SERVICE_PAUSED', 'SERVICE_RUNNING', 'SERVICE_START_PENDING', 'SERVICE_STOP_PENDING',
    'SERVICE_STOPPED',
  ],
  service_type_ov: ['SERVICE_KERNEL_DRIVER', 'SERVICE_FILE_SYSTEM_DRIVER', 'SERVICE_WIN32_OWN_PROCESS', 'SERVICE_WIN32_SHARE_PROCESS'],
  start_type_ov: ['SERVICE_AUTO_START', 'SERVICE_BOOT_START', 'SERVICE_DEMAND_START', 'SERVICE_DISABLED', 'SERVICE_SYSTEM_ALERT'],
  threat_actor_group_type_ov: [
    'activist', 'competitor', 'crime-syndicate', 'criminal', 'hacker', 'insider-accidental', 'insider-disgruntled', 'nation-state', 'sensationalist',
    'spy', 'terrorist', 'unknown',
  ],
  threat_actor_group_role_ov: [
    'agent', 'director', 'independent', 'infrastructure-architect', 'infrastructure-operator', 'malware-author', 'sponsor',
  ],
  threat_actor_group_sophistication_ov: ['none', 'minimal', 'intermediate', 'advanced', 'expert', 'innovator', 'strategic'],
  threat_actor_individual_type_ov: [
    'activist', 'competitor', 'crime-syndicate', 'criminal', 'hacker', 'insider-accidental', 'insider-disgruntled', 'nation-state', 'sensationalist',
    'spy', 'terrorist', 'unknown',
  ],
  threat_actor_individual_role_ov: [
    'agent', 'director', 'independent', 'infrastructure-architect', 'infrastructure-operator', 'malware-author', 'sponsor',
  ],
  threat_actor_individual_sophistication_ov: ['none', 'minimal', 'intermediate', 'advanced', 'expert', 'innovator', 'strategic'],
  tool_types_ov: [
    'denial-of-service', 'exploitation', 'information-gathering', 'network-capture', 'credential-exploitation', 'remote-access',
    'vulnerability-scanning', 'unknown',
  ],
  gender_ov: ['male', 'female', 'nonbinary', 'other', 'unknown'],
  marital_status_ov: [
    'annulled', 'divorced', 'domestic_partner', 'legally_separated', 'separated', 'married', 'never_married', 'polygamous', 'single', 'widowed',
  ],
  hair_color_ov: ['black', 'brown', 'blond', 'red', 'green', 'blue', 'gray', 'bald', 'other'],
  eye_color_ov: ['black', 'brown', 'green', 'blue', 'hazel', 'other'],
  key_type_ov: ['rsa', 'ecdsa', 'ed25519', 'dsa'],
};
const byNames = (names: string[]) => names.map((name) => ({ name }));
// Types absent from this list (Settings, EntitySetting, ManagerConfiguration, Capability) only have built-in instances
const BUILT_IN_ELEMENTS: Record<string, NaturalKey[]> = {
  [ENTITY_TYPE_ROLE]: byNames(['Default', 'Administrator', 'Connector']),
  [ENTITY_TYPE_GROUP]: byNames(['Default', 'Administrators', 'Connectors']),
  [ENTITY_TYPE_STATUS_TEMPLATE]: byNames(['NEW', 'IN_PROGRESS', 'PENDING', 'TO_BE_QUALIFIED', 'ANALYZED', 'CLOSED', 'DECLINED', 'APPROVED']),
  [ENTITY_TYPE_STATUS]: [
    ...['NEW', 'IN_PROGRESS', 'ANALYZED', 'CLOSED'].map((template) => ({ type: 'Report', scope: 'GLOBAL', template })),
    ...['NEW', 'DECLINED', 'APPROVED'].map((template) => ({ type: 'Case-Rfi', scope: 'REQUEST_ACCESS', template })),
  ],
  [ENTITY_TYPE_VOCABULARY]: Object.entries(BUILT_IN_VOCABULARIES).flatMap(([category, names]) => names.map((name) => ({ category, name }))),
  [ENTITY_TYPE_MARKING_DEFINITION]: [
    ...['TLP:CLEAR', 'TLP:GREEN', 'TLP:AMBER', 'TLP:AMBER+STRICT', 'TLP:RED'].map((definition) => ({ definition_type: 'TLP', definition })),
    ...['PAP:CLEAR', 'PAP:GREEN', 'PAP:AMBER', 'PAP:RED'].map((definition) => ({ definition_type: 'PAP', definition })),
  ],
  [ENTITY_TYPE_THEME]: byNames(['Filigran Dark', 'Filigran Light']),
  [ENTITY_TYPE_EMAIL_TEMPLATE]: byNames(['Built-In Template For Onboarding']),
  [ENTITY_TYPE_NOTIFIER]: byNames(['Sample of Microsoft Teams message for live trigger', 'Sample of Microsoft Teams message for digest trigger']),
  [ENTITY_TYPE_RETENTION_RULE]: ['file', 'workbench', 'history', 'activity'].map((scope) => ({ scope })),
  [ENTITY_TYPE_FINTEL_TEMPLATE]: [
    ...['Report', 'Grouping', 'Case-Incident', 'Case-Rfi', 'Case-Rft'].map((target_type) => ({ name: 'Executive Summary', target_type })),
    { name: 'Incident Response Report', target_type: 'Case-Incident' },
  ],
};
// endregion

// Natural key of a stored element: the one used to compute its export_id at creation
type NaturalKeyResolver = (element: StoredElement, statusTemplateNames: Map<string, string>) => NaturalKey | undefined;
const byName: NaturalKeyResolver = (element) => ({ name: element.name });
const builtInFlaggedByName: NaturalKeyResolver = (element) => (element.built_in === true ? { name: element.name } : undefined);
const NATURAL_KEY_RESOLVERS: Record<string, NaturalKeyResolver> = {
  [ENTITY_TYPE_SETTINGS]: () => ({}),
  [ENTITY_TYPE_ENTITY_SETTING]: (element) => ({ target_type: element.target_type }),
  [ENTITY_TYPE_MANAGER_CONFIGURATION]: (element) => ({ manager_id: element.manager_id }),
  [ENTITY_TYPE_CAPABILITY]: byName,
  [ENTITY_TYPE_ROLE]: byName,
  [ENTITY_TYPE_GROUP]: byName,
  [ENTITY_TYPE_STATUS_TEMPLATE]: byName,
  [ENTITY_TYPE_STATUS]: (element, statusTemplateNames) => {
    return { type: element.type, scope: element.scope, template: statusTemplateNames.get(element.template_id) ?? '' };
  },
  [ENTITY_TYPE_VOCABULARY]: (element) => ({ category: element.category, name: element.name }),
  [ENTITY_TYPE_MARKING_DEFINITION]: (element) => ({ definition_type: element.definition_type, definition: element.definition }),
  [ENTITY_TYPE_THEME]: builtInFlaggedByName,
  [ENTITY_TYPE_EMAIL_TEMPLATE]: byName,
  [ENTITY_TYPE_NOTIFIER]: byName,
  [ENTITY_TYPE_RETENTION_RULE]: (element) => ({ scope: element.scope }),
  [ENTITY_TYPE_FINTEL_TEMPLATE]: (element) => ({ name: element.name, target_type: [element.settings_types].flat()[0] }),
};
export const BUILT_IN_EXPORT_ID_TYPES = Object.keys(NATURAL_KEY_RESOLVERS);

const BUILT_IN_EXPORT_IDS = new Set(Object.entries(BUILT_IN_ELEMENTS)
  .flatMap(([entityType, naturalKeys]) => naturalKeys.map((naturalKey) => generateBuiltInExportId(entityType, naturalKey))));

const buildStatusTemplateNames = (elements: StoredElement[]) => new Map(elements
  .filter((element) => element.entity_type === ENTITY_TYPE_STATUS_TEMPLATE)
  .map((element) => [element.internal_id, element.name]));

// Returns the export_id of the element if it is a built-in one, undefined otherwise
const resolveBuiltInExportId = (element: StoredElement, statusTemplateNames: Map<string, string>) => {
  const naturalKey = NATURAL_KEY_RESOLVERS[element.entity_type]?.(element, statusTemplateNames);
  if (!naturalKey) {
    return undefined;
  }
  const exportId = generateBuiltInExportId(element.entity_type, naturalKey);
  const isBuiltIn = !BUILT_IN_ELEMENTS[element.entity_type] || BUILT_IN_EXPORT_IDS.has(exportId);
  return isBuiltIn ? exportId : undefined;
};

// Built-in elements created by an older migration, run just before this one during the same upgrade,
// got their internal_id as export_id at creation, like any configuration element: it must be replaced.
const hasNoBuiltInExportId = (element: StoredElement) => !element.export_id || element.export_id === element.internal_id;

// Computes the export_id each built-in element must have, and returns the elements that do not have it yet.
export const computeMissingBuiltInExportIds = (elements: StoredElement[]): ExportIdAssignment[] => {
  const statusTemplateNames = buildStatusTemplateNames(elements);
  const candidatesByExportId = new Map<string, StoredElement[]>();
  for (let index = 0; index < elements.length; index += 1) {
    const element = elements[index];
    const exportId = resolveBuiltInExportId(element, statusTemplateNames);
    if (exportId) {
      candidatesByExportId.set(exportId, [...(candidatesByExportId.get(exportId) ?? []), element]);
    }
  }
  const assignments: ExportIdAssignment[] = [];
  candidatesByExportId.forEach((candidates, exportId) => {
    // An export_id must identify a single element. If several ones match the same built-in
    // (a copy with the same name for instance), the oldest is kept: built-in elements are created at platform init.
    const alreadyAssigned = candidates.some((candidate) => candidate.export_id === exportId);
    const [oldest] = R.sortBy((candidate) => candidate.created_at ?? '', candidates.filter(hasNoBuiltInExportId));
    if (!alreadyAssigned && oldest) {
      assignments.push({ element: oldest, export_id: exportId });
    }
    if (candidates.length > 1) {
      const ids = candidates.map((candidate) => candidate.internal_id).join(', ');
      logMigration.info(`${message} > ${candidates.length} ${candidates[0].entity_type} match the same built-in element (${ids}), only one gets the export_id`);
    }
  });
  return assignments;
};

// Lists the built-in elements that cannot be found, because an administrator renamed or deleted them for instance
export const findMissingBuiltInElements = (elements: StoredElement[]): { entity_type: string; naturalKey: NaturalKey }[] => {
  const statusTemplateNames = buildStatusTemplateNames(elements);
  const foundExportIds = new Set(elements.flatMap((element) => [element.export_id, resolveBuiltInExportId(element, statusTemplateNames)]));
  return Object.entries(BUILT_IN_ELEMENTS).flatMap(([entity_type, naturalKeys]) => naturalKeys
    .filter((naturalKey) => !foundExportIds.has(generateBuiltInExportId(entity_type, naturalKey)))
    .map((naturalKey) => ({ entity_type, naturalKey })));
};

export const up = async (next: (error?: Error) => void) => {
  const startTime = Date.now();
  logMigration.info(`${message} > started`);
  const context = executionContext('migration');
  const indices = [READ_INDEX_INTERNAL_OBJECTS, READ_INDEX_STIX_META_OBJECTS];
  const elements = await elList<any>(context, SYSTEM_USER, indices, { types: BUILT_IN_EXPORT_ID_TYPES });
  const missingByType = R.groupBy((missing) => missing.entity_type, findMissingBuiltInElements(elements));
  Object.entries(missingByType).forEach(([entityType, missing]) => {
    const naturalKeys = (missing ?? []).map(({ naturalKey }) => JSON.stringify(naturalKey)).join(', ');
    logMigration.warn(`${message} > ${missing?.length} built-in ${entityType} not found (renamed or deleted), they get their internal_id as export_id: ${naturalKeys}`);
  });
  const assignments = computeMissingBuiltInExportIds(elements);
  const countByType = R.countBy((assignment) => assignment.element.entity_type, assignments);
  Object.entries(countByType).forEach(([entityType, count]) => {
    logMigration.info(`${message} > ${count} built-in ${entityType} to update`);
  });
  let currentProcessing = 0;
  const concurrentUpdate = async (group: ExportIdAssignment[]) => {
    const bulk = group.flatMap(({ element, export_id }) => [
      { update: { _index: element._index, _id: element._id ?? element.internal_id } },
      {
        script: {
          source: 'if (ctx._source.export_id == null || ctx._source.export_id == ctx._source.internal_id) '
            + '{ ctx._source.export_id = params.export_id; } else { ctx.op = \'noop\'; }',
          params: { export_id },
        },
      },
    ]);
    await elBulk(context, { refresh: true, timeout: BULK_TIMEOUT, body: bulk });
    currentProcessing += group.length;
    logMigration.info(`${message} > updated ${currentProcessing} / ${assignments.length}`);
  };
  await BluePromise.map(R.splitEvery(MAX_BULK_OPERATIONS, assignments), concurrentUpdate, { concurrency: ES_MAX_CONCURRENCY });
  logMigration.info(`${message} > done in ${Date.now() - startTime} ms`);
  next();
};

export const down = async (next: (error?: Error) => void) => {
  next();
};
