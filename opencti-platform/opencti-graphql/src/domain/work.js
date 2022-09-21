import moment from 'moment';
import * as R from 'ramda';
import {
  elDeleteInstances,
  elIndex,
  elLoadById,
  elPaginate,
  elUpdate,
} from '../database/engine';
import { generateWorkId } from '../schema/identifier';
import { INDEX_HISTORY, isNotEmptyField, READ_INDEX_HISTORY } from '../database/utils';
import {
  redisDeleteWorks,
  redisGetWork,
  redisUpdateActionExpectation,
  redisUpdateWorkFigures
} from '../database/redis';
import { ENTITY_TYPE_WORK } from '../schema/internalObject';
import { now, sinceNowInMinutes } from '../utils/format';
import { CONNECTOR_INTERNAL_EXPORT_FILE } from '../schema/general';

export const workToExportFile = (work) => {
  const lastModifiedSinceMin = sinceNowInMinutes(work.updated_at);
  const isWorkActive = lastModifiedSinceMin < 20; // Timeout if no activity during 20 minutes
  return {
    id: work.internal_id,
    name: work.name || 'Unknown',
    size: 0,
    lastModified: moment(work.updated_at).toDate(),
    lastModifiedSinceMin,
    uploadStatus: isWorkActive ? work.status : 'timeout',
    metaData: {
      messages: work.messages,
      errors: work.errors,
    },
  };
};

const loadWorkById = async (user, workId) => {
  const action = await elLoadById(user, workId, ENTITY_TYPE_WORK, READ_INDEX_HISTORY);
  return action ? R.assoc('id', workId, action) : action;
};

export const findById = (user, workId) => {
  return loadWorkById(user, workId);
};

export const findAll = (user, args = {}) => {
  const finalArgs = R.pipe(
    R.assoc('type', ENTITY_TYPE_WORK),
    R.assoc('orderBy', args.orderBy || 'timestamp'),
    R.assoc('orderMode', args.orderMode || 'desc')
  )(args);
  return elPaginate(user, READ_INDEX_HISTORY, finalArgs);
};

export const worksForConnector = async (user, connectorId, args = {}) => {
  const { first = 10, filters = [] } = args;
  filters.push({ key: 'connector_id', values: [connectorId] });
  return elPaginate(user, READ_INDEX_HISTORY, {
    type: ENTITY_TYPE_WORK,
    connectionFormat: false,
    orderBy: 'timestamp',
    orderMode: 'desc',
    first,
    filters,
  });
};

export const worksForSource = async (user, sourceId, args = {}) => {
  const { first = 10, filters = [], type } = args;
  const basicFilters = [{ key: 'event_source_id', values: [sourceId] }];
  if (type) basicFilters.push({ key: 'event_type', values: [type] });
  return elPaginate(user, READ_INDEX_HISTORY, {
    type: ENTITY_TYPE_WORK,
    connectionFormat: false,
    orderBy: 'timestamp',
    orderMode: 'desc',
    first,
    filters: [...basicFilters, ...filters],
  });
};

export const loadExportWorksAsProgressFiles = async (user, sourceId) => {
  const works = await worksForSource(user, sourceId, { type: CONNECTOR_INTERNAL_EXPORT_FILE, first: 10 });
  const filterSuccessCompleted = R.filter((w) => w.status !== 'complete' || w.errors.length > 0, works);
  return R.map((item) => workToExportFile(item), filterSuccessCompleted);
};

export const deleteWorksRaw = async (works) => {
  const workIds = works.map((w) => w.internal_id);
  await elDeleteInstances(works);
  await redisDeleteWorks(workIds);
  return workIds;
};

export const deleteWork = async (user, workId) => {
  const work = await loadWorkById(user, workId);
  if (work) {
    await deleteWorksRaw([work]);
  }
  return workId;
};

export const pingWork = async (user, workId) => {
  const params = { updated_at: now() };
  const source = 'ctx._source["updated_at"] = params.updated_at;';
  await elUpdate(INDEX_HISTORY, workId, {
    script: { source, lang: 'painless', params },
  });
  return workId;
};

export const deleteWorkForConnector = async (user, connectorId) => {
  let works = await worksForConnector(user, connectorId, { first: 500 });
  while (works.length > 0) {
    await deleteWorksRaw(works);
    works = await worksForConnector(user, connectorId, { first: 500 });
  }
  return true;
};

export const deleteWorkForFile = async (user, fileId) => {
  const works = await worksForSource(user, fileId);
  if (works.length > 0) {
    await deleteWorksRaw(works);
  }
  return true;
};

export const createWork = async (user, connector, friendlyName, sourceId, args = {}) => {
  // Create the new work
  const { receivedTime = null } = args;
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
  };
  await elIndex(INDEX_HISTORY, work);
  return loadWorkById(user, workId);
};

const isWorkCompleted = async (workId) => {
  const { import_processed_number: pn, import_expected_number: en } = await redisGetWork(workId);
  return { isComplete: parseInt(pn, 10) === parseInt(en, 10), total: pn };
};

export const reportExpectation = async (user, workId, errorData) => {
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
    // To avoid maximum string in Elastic (536870888), arbitrary limit the number of possible errors in a work to 5000 (5000*50000 < 536870888)
    if (errorData) {
      const { error, source } = errorData;
      sourceScript += 'if (ctx._source.errors.length < 5000) { ctx._source.errors.add(["timestamp": params.now, "message": params.error, "source": params.source]); }';
      params.source = source;
      params.error = error;
    }
    // Update elastic
    await elUpdate(INDEX_HISTORY, workId, { script: { source: sourceScript, lang: 'painless', params } });
    // Remove redis work if needed
    if (isComplete) {
      await redisDeleteWorks(workId);
    }
  }
  return workId;
};

export const updateExpectationsNumber = async (user, workId, expectations) => {
  const params = { updated_at: now(), import_expected_number: expectations };
  let source = 'ctx._source.updated_at = params.updated_at;';
  source += 'ctx._source["import_expected_number"] = ctx._source["import_expected_number"] + params.import_expected_number;';
  await elUpdate(INDEX_HISTORY, workId, { script: { source, lang: 'painless', params } });
  return redisUpdateActionExpectation(user, workId, expectations);
};

export const updateReceivedTime = async (user, workId, message) => {
  const params = { received_time: now(), message };
  let source = 'ctx._source.status = "progress";';
  source += 'ctx._source["received_time"] = params.received_time;';
  if (isNotEmptyField(message)) {
    source += 'ctx._source.messages.add(["timestamp": params.received_time, "message": params.message]); ';
  }
  // Update elastic
  await elUpdate(INDEX_HISTORY, workId, { script: { source, lang: 'painless', params } });
  return workId;
};

export const updateProcessedTime = async (user, workId, message, inError = false) => {
  const params = { processed_time: now(), message };
  let source = 'ctx._source["processed_time"] = params.processed_time;';
  const currentWork = await loadWorkById(user, workId);
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
  await elUpdate(INDEX_HISTORY, workId, { script: { source, lang: 'painless', params } });
  // Remove redis work if needed
  if (isComplete) {
    await redisDeleteWorks([workId]);
  }
  return workId;
};
