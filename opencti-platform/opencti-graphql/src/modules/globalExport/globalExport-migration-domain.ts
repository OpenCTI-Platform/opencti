import * as R from 'ramda';
import { Promise as BluePromise } from 'bluebird';
import { logMigration } from '../../config/conf';
import { BULK_TIMEOUT, elBulk, elList, ES_MAX_CONCURRENCY, MAX_BULK_OPERATIONS } from '../../database/engine';
import { READ_INDEX_INTERNAL_OBJECTS, READ_INDEX_STIX_META_OBJECTS } from '../../database/utils';
import { SYSTEM_USER } from '../../utils/access';
import type { AuthContext } from '../../types/user';
import { generateBuiltInExportId } from '../../schema/identifier';
import { BUILT_IN_EXPORT_ID_SPECS, BUILT_IN_EXPORT_ID_TYPES, builtInExportIdOf, type NaturalKey } from './globalExport-built-ins';

const message = '[MIGRATION] Add export_id to built-in entities';

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

const BUILT_IN_EXPORT_IDS = new Set(BUILT_IN_EXPORT_ID_SPECS
  .flatMap(({ entityType, builtIns }) => builtIns.map((naturalKey) => generateBuiltInExportId(entityType, naturalKey))));

// Returns the export_id of the element if it is a built-in one, undefined otherwise
const resolveBuiltInExportId = (element: StoredElement) => {
  const exportId = builtInExportIdOf(element.entity_type, element);
  return exportId && BUILT_IN_EXPORT_IDS.has(exportId) ? exportId : undefined;
};

// Computes the export_id each built-in element must have, and returns the elements that do not have it yet.
export const computeMissingBuiltInExportIds = (elements: StoredElement[]): ExportIdAssignment[] => {
  const candidatesByExportId = new Map<string, StoredElement[]>();
  for (let index = 0; index < elements.length; index += 1) {
    const element = elements[index];
    const exportId = resolveBuiltInExportId(element);
    if (exportId) {
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

// Lists the built-in elements that cannot be found, because an administrator renamed or deleted them for instance
export const findMissingBuiltInElements = (elements: StoredElement[]): { entity_type: string; naturalKey: NaturalKey }[] => {
  const foundExportIds = new Set(elements.flatMap((element) => [element.export_id, resolveBuiltInExportId(element)]));
  return BUILT_IN_EXPORT_ID_SPECS.flatMap(({ entityType, builtIns }) => builtIns
    .filter((naturalKey) => !foundExportIds.has(generateBuiltInExportId(entityType, naturalKey)))
    .map((naturalKey) => ({ entity_type: entityType, naturalKey })));
};

// Gives their export_id to the built-in elements of a platform created before the export_id existed.
// Not called yet: the migration calling it is added once every global export/import feature is done.
export const addMissingBuiltInExportIds = async (context: AuthContext) => {
  const startTime = Date.now();
  logMigration.info(`${message} > started`);
  const indices = [READ_INDEX_INTERNAL_OBJECTS, READ_INDEX_STIX_META_OBJECTS];
  const elements = await elList<any>(context, SYSTEM_USER, indices, { types: BUILT_IN_EXPORT_ID_TYPES });
  const missingByType = R.groupBy((missing) => missing.entity_type, findMissingBuiltInElements(elements));
  Object.entries(missingByType).forEach(([entityType, missing]) => {
    const naturalKeys = (missing ?? []).map(({ naturalKey }) => JSON.stringify(naturalKey)).join(', ');
    logMigration.warn(`${message} > ${missing?.length} built-in ${entityType} not found (renamed or deleted), they get no export_id: ${naturalKeys}`);
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
};
