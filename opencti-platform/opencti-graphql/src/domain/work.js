import moment from 'moment';
import * as R from 'ramda';
import { elDeleteInstances, elIndex, elLoadById, elPaginate, elRawDeleteByQuery, elUpdate, ES_MINIMUM_FIXED_PAGINATION } from '../database/engine';
import { generateWorkId } from '../schema/identifier';
import { INDEX_HISTORY, isNotEmptyField, READ_INDEX_HISTORY } from '../database/utils';
import { isWorkCompleted, redisDeleteWorks, redisUpdateActionExpectation, redisUpdateWorkFigures } from '../database/redis';
import { ENTITY_TYPE_CONNECTOR, ENTITY_TYPE_WORK } from '../schema/internalObject';
import { now, sinceNowInMinutes } from '../utils/format';
import { BASE_TYPE_ENTITY, buildRefRelationKey, CONNECTOR_INTERNAL_EXPORT_FILE } from '../schema/general';
import { publishUserAction } from '../listener/UserActionListener';
import { AlreadyDeletedError, DatabaseError } from '../config/errors';
import { addFilter } from '../utils/filtering/filtering-utils';
import { IMPORT_CSV_CONNECTOR, IMPORT_CSV_CONNECTOR_ID } from '../connector/importCsv/importCsv';
import { RELATION_OBJECT_MARKING } from '../schema/stixRefRelationship';

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

const loadWorkById = async (context, user, workId) => {
  const action = await elLoadById(context, user, workId, { type: ENTITY_TYPE_WORK, indices: READ_INDEX_HISTORY });
  return action ? R.assoc('id', workId, action) : action;
};

export const findById = (context, user, workId) => {
  return loadWorkById(context, user, workId);
};

export const findAll = (context, user, args = {}) => {
  const finalArgs = R.pipe(
    R.assoc('type', ENTITY_TYPE_WORK),
    R.assoc('orderBy', args.orderBy || 'timestamp'),
    R.assoc('orderMode', args.orderMode || 'desc')
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

export const deleteWorksRaw = async (works) => {
  const workIds = works.map((w) => w.internal_id);
  await elDeleteInstances(works);
  await redisDeleteWorks(workIds);
  return workIds;
};

export const deleteWork = async (context, user, workId) => {
  const work = await loadWorkById(context, user, workId);
  if (work) {
    await deleteWorksRaw([work]);
    await publishUserAction({
      user,
      event_type: 'mutation',
      event_scope: 'delete',
      event_access: 'administration',
      message: `deletes Connector Work \`${work.name}\``,
      context_data: { id: workId, entity_type: ENTITY_TYPE_WORK, input: work }
    });
  }
  return workId;
};

export const pingWork = async (context, user, workId) => {
  const currentWork = await loadWorkById(context, user, workId);
  const params = { updated_at: now() };
  const source = 'ctx._source["updated_at"] = params.updated_at;';
  await elUpdate(currentWork._index, workId, { script: { source, lang: 'painless', params } });
  return workId;
};

export const deleteWorkForConnector = async (context, user, connectorId) => {
  let connector;
  if (connectorId === IMPORT_CSV_CONNECTOR_ID) {
    connector = IMPORT_CSV_CONNECTOR;
  } else {
    connector = await elLoadById(context, user, connectorId, { type: ENTITY_TYPE_CONNECTOR });
  }
  if (!connector) {
    throw AlreadyDeletedError({ connectorId });
  }
  let works = await worksForConnector(context, user, connectorId, { first: 500 });
  while (works.length > 0) {
    await deleteWorksRaw(works);
    works = await worksForConnector(context, user, connectorId, { first: 500 });
  }
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `cleans \`all works\` for connector \`${connector.name}\``,
    context_data: { id: connectorId, entity_type: ENTITY_TYPE_CONNECTOR, input: { id: connectorId } }
  });
  return true;
};

export const deleteWorkForFile = async (context, user, fileId) => {
  const works = await worksForSource(context, user, fileId);
  if (works.length > 0) {
    await deleteWorksRaw(works);
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
            { term: { 'event_source_id.keyword': { value: sourceId } } }
          ],
        }
      }
    },
  }).catch((err) => {
    throw DatabaseError('[SEARCH] Error deleting all works ', { sourceId, cause: err });
  });
};

export const createWork = async (context, user, connector, friendlyName, sourceId, args = {}) => {
  // Create the new work
  const { receivedTime = null, fileMarkings = [] } = args;
  // Create the work and an initial job
  const { id: workId, timestamp } = generateWorkId(connector.internal_id);
  const work = {
    internal_id: workId,
    timestamp,
    updated_at: now(),
    name: friendlyName,
    base_type: BASE_TYPE_ENTITY,
    entity_type: ENTITY_TYPE_WORK,
    // For specific type, specific id is required
    event_type: connector.connector_type,
    event_source_id: sourceId,
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
    messages: [],
    errors: [],
    [buildRefRelationKey(RELATION_OBJECT_MARKING)]: [...fileMarkings]
  };
  await elIndex(INDEX_HISTORY, work);
  return loadWorkById(context, user, workId);
};

export const reportExpectation = async (context, user, workId, errorData) => {
  const timestamp = now();
  const { isComplete, total } = await redisUpdateWorkFigures(workId);
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
    await elUpdate(currentWork?._index, workId, { script: { source: sourceScript, lang: 'painless', params } });
  }
  return workId;
};

export const updateExpectationsNumber = async (context, user, workId, expectations) => {
  const currentWork = await loadWorkById(context, user, workId);
  const params = { updated_at: now(), import_expected_number: expectations };
  let source = 'ctx._source.updated_at = params.updated_at;';
  source += 'ctx._source["import_expected_number"] = ctx._source["import_expected_number"] + params.import_expected_number;';
  await elUpdate(currentWork._index, workId, { script: { source, lang: 'painless', params } });
  return redisUpdateActionExpectation(user, workId, expectations);
};

export const updateReceivedTime = async (context, user, workId, message) => {
  const currentWork = await loadWorkById(context, user, workId);
  const params = { received_time: now(), message };
  let source = 'ctx._source.status = "progress";';
  source += 'ctx._source["received_time"] = params.received_time;';
  if (isNotEmptyField(message)) {
    source += 'ctx._source.messages.add(["timestamp": params.received_time, "message": params.message]); ';
  }
  // Update elastic
  await elUpdate(currentWork._index, workId, { script: { source, lang: 'painless', params } });
  return workId;
};

export const updateProcessedTime = async (context, user, workId, message, inError = false) => {
  const currentWork = await loadWorkById(context, user, workId);
  const params = { processed_time: now(), message };
  let source = 'ctx._source["processed_time"] = params.processed_time;';
  const { isComplete, total } = await isWorkCompleted(workId);
  if (currentWork.import_expected_number === 0 || isComplete) {
    params.completed_number = total ?? 0;
    source += `ctx._source['status'] = "complete";
               ctx._source['completed_number'] = params.completed_number;
               ctx._source['completed_time'] = params.processed_time;`;
  }
  if (isNotEmptyField(message)) {
    if (inError) {
      source += 'ctx._source.errors.add(["timestamp": params.processed_time, "message": params.message]); ';
    } else {
      source += 'ctx._source.messages.add(["timestamp": params.processed_time, "message": params.message]); ';
    }
  }
  // Update elastic
  await elUpdate(currentWork._index, workId, { script: { source, lang: 'painless', params } });
  // Remove redis work if needed
  if (isComplete) {
    await redisDeleteWorks([workId]);
  }
  return workId;
};
