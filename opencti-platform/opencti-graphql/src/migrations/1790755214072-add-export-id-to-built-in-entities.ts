import * as R from 'ramda';
import { Promise as BluePromise } from 'bluebird';
import { logMigration } from '../config/conf';
import { BULK_TIMEOUT, elBulk, elList, ES_MAX_CONCURRENCY, MAX_BULK_OPERATIONS } from '../database/engine';
import { READ_INDEX_INTERNAL_OBJECTS, READ_INDEX_STIX_META_OBJECTS } from '../database/utils';
import { executionContext, ROLE_ADMINISTRATOR, ROLE_DEFAULT, SYSTEM_USER } from '../utils/access';
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
import { ENTITY_TYPE_CONTAINER_REPORT } from '../schema/stixDomainObject';
import { ENTITY_TYPE_CONTAINER_CASE_RFI } from '../modules/case/case-rfi/case-rfi-types';
import { ENTITY_TYPE_ENTITY_SETTING } from '../modules/entitySetting/entitySetting-types';
import { ENTITY_TYPE_MANAGER_CONFIGURATION } from '../modules/managerConfiguration/managerConfiguration-types';
import { ENTITY_TYPE_VOCABULARY } from '../modules/vocabulary/vocabulary-types';
import { ENTITY_TYPE_DECAY_RULE } from '../modules/decayRule/decayRule-types';
import { ENTITY_TYPE_EMAIL_TEMPLATE } from '../modules/emailTemplate/emailTemplate-types';
import { ENTITY_TYPE_NOTIFIER } from '../modules/notifier/notifier-types';
import { ENTITY_TYPE_FINTEL_TEMPLATE } from '../modules/fintelTemplate/fintelTemplate-types';
import { StatusScope, VocabularyCategory } from '../generated/graphql';
import { GROUP_DEFAULT } from '../domain/group';
import { openVocabularies } from '../modules/vocabulary/vocabulary-utils';
import { BUILT_IN_DECAY_RULES } from '../modules/decayRule/decayRule-domain';
import { DEFAULT_TEAM_DIGEST_MESSAGE, DEFAULT_TEAM_MESSAGE } from '../modules/notifier/notifier-statics';
import { DEFAULT_EMAIL_TEMPLATE_INPUT } from '../database/default-email-template-input';

const message = '[MIGRATION] Add export_id to built-in entities';

// region built-in elements, as created by the platform initialization (see data-initialization.js)
const BUILT_IN_ROLES = [ROLE_DEFAULT, ROLE_ADMINISTRATOR, 'Connector'];
const BUILT_IN_GROUPS = [GROUP_DEFAULT, 'Administrators', 'Connectors'];
const BUILT_IN_STATUS_TEMPLATES = ['NEW', 'IN_PROGRESS', 'PENDING', 'TO_BE_QUALIFIED', 'ANALYZED', 'CLOSED', 'DECLINED', 'APPROVED'];
const BUILT_IN_STATUSES = [
  ...['NEW', 'IN_PROGRESS', 'ANALYZED', 'CLOSED'].map((template) => ({ type: ENTITY_TYPE_CONTAINER_REPORT, scope: StatusScope.Global, template })),
  ...['NEW', 'DECLINED', 'APPROVED'].map((template) => ({ type: ENTITY_TYPE_CONTAINER_CASE_RFI, scope: StatusScope.RequestAccess, template })),
];
const BUILT_IN_MARKINGS = [
  ...['TLP:CLEAR', 'TLP:GREEN', 'TLP:AMBER', 'TLP:AMBER+STRICT', 'TLP:RED'].map((definition) => ({ definition_type: 'TLP', definition })),
  ...['PAP:CLEAR', 'PAP:GREEN', 'PAP:AMBER', 'PAP:RED'].map((definition) => ({ definition_type: 'PAP', definition })),
];
const BUILT_IN_THEMES = ['Filigran Dark', 'Filigran Light'];
const BUILT_IN_DECAY_RULE_NAMES = BUILT_IN_DECAY_RULES.map((rule) => rule.name);
const BUILT_IN_NOTIFIERS = [DEFAULT_TEAM_MESSAGE.name, DEFAULT_TEAM_DIGEST_MESSAGE.name];
const BUILT_IN_RETENTION_SCOPES = ['file', 'workbench', 'history', 'activity'];
const BUILT_IN_FINTEL_TEMPLATES = [
  ...['Report', 'Grouping', 'Case-Incident', 'Case-Rfi', 'Case-Rft'].map((target_type) => ({ name: 'Executive Summary', target_type })),
  { name: 'Incident Response Report', target_type: 'Case-Incident' },
];
// endregion

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
type NaturalKey = Record<string, string>;
// Returns the natural key of the element if it is a built-in one, undefined otherwise
type NaturalKeyResolver = (element: StoredElement, statusTemplateNames: Map<string, string>) => NaturalKey | undefined;

const byName = (builtInNames: string[]): NaturalKeyResolver => (element) => {
  return builtInNames.includes(element.name) ? { name: element.name } : undefined;
};
const builtInFlaggedByName = (builtInNames: string[]): NaturalKeyResolver => (element) => {
  return element.built_in === true && builtInNames.includes(element.name) ? { name: element.name } : undefined;
};

const NATURAL_KEY_RESOLVERS: Record<string, NaturalKeyResolver> = {
  [ENTITY_TYPE_SETTINGS]: () => ({}),
  [ENTITY_TYPE_ENTITY_SETTING]: (element) => ({ target_type: element.target_type }),
  [ENTITY_TYPE_MANAGER_CONFIGURATION]: (element) => ({ manager_id: element.manager_id }),
  [ENTITY_TYPE_CAPABILITY]: (element) => ({ name: element.name }),
  [ENTITY_TYPE_ROLE]: byName(BUILT_IN_ROLES),
  [ENTITY_TYPE_GROUP]: byName(BUILT_IN_GROUPS),
  [ENTITY_TYPE_STATUS_TEMPLATE]: byName(BUILT_IN_STATUS_TEMPLATES),
  [ENTITY_TYPE_STATUS]: (element, statusTemplateNames) => {
    const key = { type: element.type, scope: element.scope, template: statusTemplateNames.get(element.template_id) ?? '' };
    return BUILT_IN_STATUSES.some((builtIn) => R.equals(builtIn, key)) ? key : undefined;
  },
  [ENTITY_TYPE_VOCABULARY]: (element) => {
    const builtInVocabularies = openVocabularies[element.category as VocabularyCategory] ?? [];
    // Some keys have surrounding spaces, that are trimmed when the vocabulary is stored
    return builtInVocabularies.some(({ key }) => key.trim() === element.name) ? { category: element.category, name: element.name } : undefined;
  },
  [ENTITY_TYPE_MARKING_DEFINITION]: (element) => {
    const key = { definition_type: element.definition_type, definition: element.definition };
    return BUILT_IN_MARKINGS.some((builtIn) => R.equals(builtIn, key)) ? key : undefined;
  },
  [ENTITY_TYPE_THEME]: builtInFlaggedByName(BUILT_IN_THEMES),
  [ENTITY_TYPE_DECAY_RULE]: builtInFlaggedByName(BUILT_IN_DECAY_RULE_NAMES),
  [ENTITY_TYPE_EMAIL_TEMPLATE]: byName([DEFAULT_EMAIL_TEMPLATE_INPUT.name]),
  [ENTITY_TYPE_NOTIFIER]: byName(BUILT_IN_NOTIFIERS),
  [ENTITY_TYPE_RETENTION_RULE]: (element) => {
    return BUILT_IN_RETENTION_SCOPES.includes(element.scope) ? { scope: element.scope } : undefined;
  },
  [ENTITY_TYPE_FINTEL_TEMPLATE]: (element) => {
    const [target_type] = [element.settings_types].flat();
    const key = { name: element.name, target_type };
    return BUILT_IN_FINTEL_TEMPLATES.some((builtIn) => R.equals(builtIn, key)) ? key : undefined;
  },
};
export const BUILT_IN_EXPORT_ID_TYPES = Object.keys(NATURAL_KEY_RESOLVERS);

// Computes the export_id each built-in element must have, and returns the elements that do not have it yet.
export const computeMissingBuiltInExportIds = (elements: StoredElement[]): ExportIdAssignment[] => {
  const statusTemplateNames = new Map(elements
    .filter((element) => element.entity_type === ENTITY_TYPE_STATUS_TEMPLATE)
    .map((element) => [element.internal_id, element.name]));
  const candidatesByExportId = new Map<string, StoredElement[]>();
  for (let index = 0; index < elements.length; index += 1) {
    const element = elements[index];
    const naturalKey = NATURAL_KEY_RESOLVERS[element.entity_type]?.(element, statusTemplateNames);
    if (naturalKey) {
      const exportId = generateBuiltInExportId(element.entity_type, naturalKey);
      candidatesByExportId.set(exportId, [...(candidatesByExportId.get(exportId) ?? []), element]);
    }
  }
  const assignments: ExportIdAssignment[] = [];
  candidatesByExportId.forEach((candidates, exportId) => {
    // An export_id must identify a single element. If several ones match the same built-in
    // (a copy with the same name for instance), the oldest is kept: built-in elements are created at platform init.
    const alreadyAssigned = candidates.some((candidate) => candidate.export_id === exportId);
    const [oldest] = R.sortBy((candidate) => candidate.created_at ?? '', candidates.filter((candidate) => !candidate.export_id));
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

export const up = async (next: (error?: Error) => void) => {
  const startTime = Date.now();
  logMigration.info(`${message} > started`);
  const context = executionContext('migration');
  const indices = [READ_INDEX_INTERNAL_OBJECTS, READ_INDEX_STIX_META_OBJECTS];
  const elements = await elList<any>(context, SYSTEM_USER, indices, { types: BUILT_IN_EXPORT_ID_TYPES });
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
          source: 'if (ctx._source.export_id == null) { ctx._source.export_id = params.export_id; } else { ctx.op = \'noop\'; }',
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
