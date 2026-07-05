import moment from 'moment';
import * as R from 'ramda';
import { logApp } from '../config/conf';
import { AlreadyDeletedError, DatabaseError } from '../config/errors';
import { IMPORT_CSV_CONNECTOR, IMPORT_CSV_CONNECTOR_ID } from '../connector/importCsv/importCsv';
import { elDeleteInstances, elIndex, elLoadById, elPaginate, elRawDeleteByQuery, elUpdate, ES_MINIMUM_FIXED_PAGINATION } from '../database/engine';
import { internalLoadById } from '../database/middleware-loader';
import {
  redisDeleteWorks,
  redisGetWork,
  redisGetWorkCompletionState,
  redisInitializeWork,
  redisMarkWorkAsProcessed,
  redisUpdateActionExpectation,
  redisUpdateWorkFigures,
} from '../database/redis';
import { INDEX_HISTORY, isNotEmptyField, READ_INDEX_HISTORY } from '../database/utils';
import { publishUserAction } from '../listener/UserActionListener';
import { DRAFT_VALIDATION_CONNECTOR, DRAFT_VALIDATION_CONNECTOR_ID } from '../modules/draftWorkspace/draftWorkspace-connector';
import { reportWorkflowAsyncActionResult } from '../modules/workflow/domain/workflow-async-completion';
import { buildRefRelationKey, CONNECTOR_INTERNAL_EXPORT_FILE } from '../schema/general';
import { generateWorkId } from '../schema/identifier';
import { ENTITY_TYPE_BACKGROUND_TASK, ENTITY_TYPE_CONNECTOR, ENTITY_TYPE_WORK } from '../schema/internalObject';
import { RELATION_OBJECT_MARKING } from '../schema/stixRefRelationship';
import { addFilter } from '../utils/filtering/filtering-utils';
import { now, sinceNowInMinutes } from '../utils/format';
import { addIngestionObjectsProcessedCount } from '../manager/telemetryManager';

export const workToExportFile = (work) => {
  const lastModifiedSinceMin = sinceNowInMinutes(work.updated_at);
  const isWorkActive = lastModifiedSinceMin < 20; // Timeout if no activity during 20 minutes
  return {
    id: work.internal_id,
    name: work.name || 'Unknown',
    size: 0,
    lastModified: moment(work.updated_at).toDate(),
    lastModifiedSinceMin,
    uploadStatus: (isWorkActive || work.status === 'complete') ? work.status : 'timeout',
    metaData: {
      messages: work.messages,
      errors: work.errors,
    },
  };
};

export const loadWorkById = async (context, user, workId) => {
  const action = await elLoadById(context, user, workId, { type: ENTITY_TYPE_WORK, indices: READ_INDEX_HISTORY });
  return action ? R.assoc('id', workId, action) : action;
};

export const findById = (context, user, workId) => {
  return loadWorkById(context, user, workId);
};

export const isWorkAlive = async (_context, _user, workId) => {
  const redisWork = await redisGetWork(workId);
  return redisWork?.is_initialized === 'true';
};

export const findWorkPaginated = (context, user, args = {}) => {
  const finalArgs = R.pipe(
    R.assoc('type', ENTITY_TYPE_WORK),
    R.assoc('orderBy', args.orderBy || 'timestamp'),
    R.assoc('orderMode', args.orderMode || 'desc'),
  )(args);
  return elPaginate(context, user, READ_INDEX_HISTORY, finalArgs);
};

export const worksForConnector = async (context, user, connectorId, args = {}) => {
  const { first = ES_MINIMUM_FIXED_PAGINATION, filters = null } = args;
  const finalFilters = addFilter(filters, 'connector_id', connectorId);
  return elPaginate(context, user, READ_INDEX_HISTORY, {
    type: ENTITY_TYPE_WORK,
    connectionFormat: false,
    orderBy: 'timestamp',
    orderMode: 'desc',
    first,
    filters: finalFilters,
  });
};

export const worksForDraft = async (context, user, draftId, args = {}) => {
  const { first = ES_MINIMUM_FIXED_PAGINATION } = args;
  const worksForDraftFilter = {
    mode: 'and',
    filters: [
      {
        key: 'draft_context',
        values: [draftId],
        operator: 'eq',
        mode: 'or',
      },
    ],
    filterGroups: [],
  };
  return elPaginate(context, user, READ_INDEX_HISTORY, {
    type: ENTITY_TYPE_WORK,
    connectionFormat: false,
    orderBy: 'timestamp',
    orderMode: 'desc',
    first,
    filters: worksForDraftFilter,
  });
};

export const worksForSource = async (context, user, sourceId, args = {}) => {
  const { first = ES_MINIMUM_FIXED_PAGINATION, filters = null, type } = args;
  let finalFilters = addFilter(filters, 'event_source_id', sourceId);
  if (type) {
    finalFilters = addFilter(finalFilters, 'event_type', type);
  }
  return elPaginate(context, user, READ_INDEX_HISTORY, {
    type: ENTITY_TYPE_WORK,
    connectionFormat: false,
    orderBy: 'timestamp',
    orderMode: 'desc',
    first,
    filters: finalFilters,
  });
};

export const loadExportWorksAsProgressFiles = async (context, user, sourceId) => {
  const works = await worksForSource(context, user, sourceId, { type: CONNECTOR_INTERNAL_EXPORT_FILE, first: 10 });
  const filterSuccessCompleted = works.filter((w) => w.status !== 'complete' || w.errors.length > 0);
  return filterSuccessCompleted.map((item) => workToExportFile(item));
};

export const deleteWorksRaw = async (context, works) => {
  const workIds = works.map((w) => w.internal_id);
  await elDeleteInstances(context, works);
  await redisDeleteWorks(workIds);
  return workIds;
};

export const deleteWork = async (context, user, workId) => {
  const work = await loadWorkById(context, user, workId);
  if (work) {
    await deleteWorksRaw(context, [work]);
    await publishUserAction({
      user,
      event_type: 'mutation',
      event_scope: 'delete',
      event_access: 'administration',
      message: `deletes Connector Work \`${work.name}\``,
      context_data: { id: workId, entity_type: ENTITY_TYPE_WORK, input: work },
    });
  }
  return workId;
};

export const pingWork = async (context, user, workId) => {
  const currentWork = await loadWorkById(context, user, workId);
  const params = { updated_at: now() };
  const source = 'ctx._source["updated_at"] = params.updated_at;';
  await elUpdate(context, currentWork._index, workId, { script: { source, lang: 'painless', params } });
  return workId;
};

export const deleteWorkForConnector = async (context, user, connectorId) => {
  let connector;
  if (connectorId === IMPORT_CSV_CONNECTOR_ID) {
    connector = IMPORT_CSV_CONNECTOR;
  } else if (connectorId === DRAFT_VALIDATION_CONNECTOR_ID) {
    connector = DRAFT_VALIDATION_CONNECTOR;
  } else {
    connector = await elLoadById(context, user, connectorId, { type: ENTITY_TYPE_CONNECTOR });
  }
  if (!connector) {
    throw AlreadyDeletedError({ connectorId });
  }
  let works = await worksForConnector(context, user, connectorId, { first: 500 });
  while (works.length > 0) {
    await deleteWorksRaw(context, works);
    works = await worksForConnector(context, user, connectorId, { first: 500 });
  }
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `cleans \`all works\` for connector \`${connector.name}\``,
    context_data: { id: connectorId, entity_type: ENTITY_TYPE_CONNECTOR, input: { id: connectorId } },
  });
  return true;
};

export const deleteWorkForFile = async (context, user, fileId) => {
  const works = await worksForSource(context, user, fileId);
  if (works.length > 0) {
    await deleteWorksRaw(context, works);
  }
  return true;
};

export const deleteWorkForSource = async (sourceId) => {
  await elRawDeleteByQuery({
    index: READ_INDEX_HISTORY,
    refresh: true,
    body: {
      query: {
        bool: {
          must: [
            { term: { 'entity_type.keyword': { value: ENTITY_TYPE_WORK } } },
            { term: { 'event_source_id.keyword': { value: sourceId } } },
          ],
        },
      },
    },
  }).catch((err) => {
    throw DatabaseError('[SEARCH] Error deleting all works ', { sourceId, cause: err });
  });
};

export const createWork = async (context, user, connector, friendlyName, sourceId, args = {}) => {
  // Create the new work
  const {
    receivedTime = null,
    background_task_id,
    fileMarkings = [],
    draftContext,
  } = args;
  const isMultiPartWork = args.isMultiPartWork === true;
  // Create the work and an initial job
  const { id: workId, timestamp } = generateWorkId(connector.internal_id);
  const work = {
    internal_id: workId,
    timestamp,
    updated_at: now(),
    name: friendlyName,
    entity_type: ENTITY_TYPE_WORK,
    // For specific type, specific id is required
    event_type: connector.connector_type,
    event_source_id: sourceId,
    background_task_id,
    // Users
    user_id: user.id, // User asking for the action
    connector_id: connector.internal_id, // Connector responsible for the action
    // Action context
    status: receivedTime ? 'progress' : 'wait', // Wait / Progress / Complete
    import_expected_number: 0,
    received_time: receivedTime,
    processed_time: null,
    completed_time: null,
    completed_number: 0,
    is_multipart: isMultiPartWork,
    messages: [],
    errors: [],
    [buildRefRelationKey(RELATION_OBJECT_MARKING)]: [...fileMarkings],
  };
  if (draftContext) {
    work.draft_context = draftContext;
  }
  await elIndex(INDEX_HISTORY, work);
  const createdWork = await loadWorkById(context, user, workId);
  // If work was created, initialize work on redis
  if (createdWork) {
    await redisInitializeWork(createdWork.id, isMultiPartWork);
  }
  logApp.info('Work initiated', {
    workId,
    connector_id: connector.internal_id,
    connector_name: connector.connector_name,
    connector_type: connector.connector_type,
  });
  return createdWork;
};

const updateWorkTaskToComplete = async (context, user, work) => {
  // Work isn't linked to a task, we can return without doing anything
  if (!work.background_task_id) {
    return;
  }
  // We update the associated task to mark the work as completed there
  const associatedTaskId = work.background_task_id;
  const associatedTask = await internalLoadById(context, user, associatedTaskId, { type: ENTITY_TYPE_BACKGROUND_TASK });
  if (associatedTask) {
    const sourceScriptUpdateWork = 'ctx._source["work_completed"] = "true"';
    await elUpdate(context, associatedTask._index, associatedTaskId, { script: { source: sourceScriptUpdateWork, lang: 'painless' } });
    // If this task was spawned by a workflow async action, report the result back to the workflow
    if (associatedTask.workflow_action_id && associatedTask.workflow_instance_id) {
      const workflowStatus = work.errors?.length > 0 ? 'failed' : 'success';
      const workflowError = work.errors?.[0]?.message;
      await reportWorkflowAsyncActionResult(
        context,
        user,
        associatedTask.workflow_instance_id,
        associatedTask.workflow_action_id,
        workflowStatus,
        workflowError,
      ).catch((err) => {
        // Non-fatal: log and continue — the admin can use clearWorkflowPendingState to recover
        logApp.error('[work] Failed to report workflow async action result', { error: err?.message, associatedTaskId });
      });
    }
  } else {
    logApp.warn('The task associated to work cannot be found in database, task work status cannot be updated.', { associatedTaskId });
  }
};

const isWorkFinished = (expected, total) => total >= expected;

// Works exist for the whole connector surface (imports, exports, analysis,
// notifications...). The ingestion volume proxy must only count import-side
// pipelines, and only on the FIRST transition to complete (reportExpectation
// and updateProcessedTime can both observe completion for the same work).
const INGESTION_WORK_EVENT_TYPES = [
  'EXTERNAL_IMPORT', // external connectors, built-in ingesters, form intakes
  'INTERNAL_IMPORT_FILE', // file imports
  'INTERNAL_ENRICHMENT', // enrichment results ingested back
  'INTERNAL_INGESTION', // draft validation
];
const countIngestionObjectsProcessed = (work, objectsCount) => {
  if (work && work.status !== 'complete' && INGESTION_WORK_EVENT_TYPES.includes(work.event_type)) {
    addIngestionObjectsProcessedCount(objectsCount);
  }
};

export const reportExpectation = async (context, user, workId, errorData) => {
  const timestamp = now();
  await redisUpdateWorkFigures(workId);
  const { expected, total, isProcessed, isMultiPartWork } = await redisGetWorkCompletionState(workId);
  const isComplete = (!isMultiPartWork || isProcessed) && isWorkFinished(expected, total);

  // Important: isWorkAlive is intentionally checked *after* redisUpdateWorkFigures, not before.
  // If we checked liveness upfront and the work closed between that check and the figures update,
  // redisUpdateWorkFigures would recreate the Redis key, potentially leaving it orphaned indefinitely
  // (i.e. if no subsequent reportExpectation/updateExpectationsNumber call would have permitted cleaning it up).
  // By checking liveness after the update, we guarantee Redis stays consistent:
  // any key recreated by redisUpdateWorkFigures is immediately removed if the work is no longer alive.
  const workAlive = await isWorkAlive(context, user, workId);
  if (!workAlive) {
    await redisDeleteWorks([workId]);
    return workId;
  }

  if (isComplete || errorData) {
    const params = { now: timestamp };
    let sourceScript = '';
    if (isComplete) {
      params.completed_number = total;
      sourceScript += `ctx._source['status'] = "complete";
      ctx._source['completed_number'] = params.completed_number;
      ctx._source['completed_time'] = params.now;`;
    }
    // To avoid maximum string in Elastic and too big memory footprint, arbitrary limit the number of possible errors in a work to 100
    if (errorData) {
      const { error, source } = errorData;
      sourceScript += 'if (ctx._source.errors.length < 100) { ctx._source.errors.add(["timestamp": params.now, "message": params.error, "source": params.source]); }';
      params.source = source;
      params.error = error;
    }
    // Update elastic
    const currentWork = await loadWorkById(context, user, workId);
    if (currentWork) {
      if (isComplete) {
        // Telemetry: objects processed by this completed work (volume proxy,
        // import-side pipelines only, first completion only).
        countIngestionObjectsProcessed(currentWork, total);
      }
      await elUpdate(context, currentWork._index, workId, { script: { source: sourceScript, lang: 'painless', params } });
      // If work is associated to a task, we also need to update work to completed on the task
      if (isComplete) {
        await updateWorkTaskToComplete(context, user, currentWork);
      }
      logApp.info('Work completed via expectation reporting', { workId, hasError: !!errorData });
    } else {
      logApp.warn('The work cannot be found in database, report expectation cannot be updated.', { workId });
    }
  }
  return workId;
};

/**
 * Called by worker to increase expected numbers.
 * @param context
 * @param user
 * @param workId
 * @param expectations
 * @returns {Promise<string>}
 */
export const updateExpectationsNumber = async (context, user, workId, expectations) => {
  await redisUpdateActionExpectation(user, workId, expectations);

  // Important: isWorkAlive is intentionally checked *after* redisUpdateActionExpectation, not before.
  // If we checked liveness upfront and the work closed between that check and the figures update,
  // redisUpdateActionExpectation would recreate the Redis key, potentially leaving it orphaned indefinitely
  // (i.e. if no subsequent reportExpectation/updateExpectationsNumber call would have permitted cleaning it up).
  // By checking liveness after the update, we guarantee Redis stays consistent:
  // any key recreated by redisUpdateActionExpectation is immediately removed if the work is no longer alive.
  // Ensure that work hasn't been deleted in the meantime in case of race condition
  const workAlive = await isWorkAlive(context, user, workId);
  if (!workAlive) {
    await redisDeleteWorks([workId]);
    logApp.warn('The work cannot be found in database, expectation cannot be updated.', { workId, expectations });
    return workId;
  }

  const currentWork = await loadWorkById(context, user, workId);
  if (!currentWork) { // work is no longer exists
    logApp.warn('The work cannot be found in database, expectation cannot be updated.', { workId, expectations });
    return workId;
  }

  const params = { updated_at: now(), import_expected_number: expectations };
  let source = 'ctx._source.updated_at = params.updated_at;';
  source += 'ctx._source["import_expected_number"] = ctx._source["import_expected_number"] + params.import_expected_number;';
  await elUpdate(context, currentWork._index, workId, { script: { source, lang: 'painless', params } });
  return workId;
};

/**
 * Called by worker to link a work to a specific draft context.
 * @param context
 * @param user
 * @param workId
 * @param draftContext
 * @returns {Promise<string>}
 */
export const addDraftContext = async (context, user, workId, draftContext) => {
  const currentWork = await loadWorkById(context, user, workId);
  if (!currentWork) { // work is no longer exists
    logApp.warn('The work cannot be found in database, draft context cannot be updated.', { workId, draftContext });
    return workId;
  }
  const params = { updated_at: now(), draft_context: draftContext };
  let source = 'ctx._source.updated_at = params.updated_at;';
  source += 'ctx._source["draft_context"] =  params.draft_context;';
  await elUpdate(context, currentWork._index, workId, { script: { source, lang: 'painless', params } });
  return workId;
};

export const updateReceivedTime = async (context, user, workId, message) => {
  const currentWork = await loadWorkById(context, user, workId);
  if (!currentWork) { // work is no longer exists
    logApp.warn('The work cannot be found in database, received time cannot be updated.', { workId });
    return workId;
  }
  const params = { received_time: now(), message };
  let source = 'ctx._source.status = "progress";';
  source += 'ctx._source["received_time"] = params.received_time;';
  if (isNotEmptyField(message)) {
    source += 'ctx._source.messages.add(["timestamp": params.received_time, "message": params.message]); ';
  }
  // Update elastic
  await elUpdate(context, currentWork._index, workId, { script: { source, lang: 'painless', params } });
  return workId;
};

export const updateProcessedTime = async (context, user, workId, message, inError = false) => {
  const currentWork = await loadWorkById(context, user, workId);
  if (!currentWork) { // work is no longer exists
    logApp.warn('The work cannot be found in database, processed time cannot be updated.', { workId });
    return workId;
  }
  const { expected, total, isMultiPartWork } = await redisGetWorkCompletionState(workId);
  const isComplete = isWorkFinished(expected, total);
  if (isMultiPartWork && !isComplete) {
    await redisMarkWorkAsProcessed(workId);
  }
  const params = { processed_time: now(), message };
  let source = 'ctx._source["processed_time"] = params.processed_time;';
  if (isComplete) {
    params.completed_number = total && !Number.isNaN(total) ? total : 1;
    source += `ctx._source['status'] = "complete";
               ctx._source['import_expected_number'] = params.completed_number;
               ctx._source['completed_number'] = params.completed_number;
               ctx._source['completed_time'] = params.processed_time;`;
    // Telemetry: objects processed by this completed work (volume proxy,
    // import-side pipelines only, first completion only). Use the real
    // processed total, not the defaulted-to-1 completed_number.
    countIngestionObjectsProcessed(currentWork, total);
  }
  if (isNotEmptyField(message)) {
    if (inError) {
      source += 'ctx._source.errors.add(["timestamp": params.processed_time, "message": params.message]); ';
    } else {
      source += 'ctx._source.messages.add(["timestamp": params.processed_time, "message": params.message]); ';
    }
  }
  // Update elastic
  await elUpdate(context, currentWork._index, workId, { script: { source, lang: 'painless', params } });
  return workId;
};
