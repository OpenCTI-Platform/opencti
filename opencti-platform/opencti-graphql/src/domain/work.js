import moment from 'moment';
import * as R from 'ramda';
import { now, sinceNowInMinutes } from '../database/middleware';
import {
  el,
  elDeleteInstanceIds,
  elIndex,
  elLoadByIds,
  elPaginate,
  elUpdate,
  INDEX_HISTORY,
} from '../database/elasticSearch';
import { CONNECTOR_INTERNAL_EXPORT_FILE, CONNECTOR_INTERNAL_IMPORT_FILE, loadConnectorById } from './connector';
import { generateWorkId } from '../schema/identifier';
import { isNotEmptyField } from '../database/utils';

export const CONNECTOR_INTERNAL_ENRICHMENT = 'INTERNAL_ENRICHMENT'; // Entity types to support (Report, Hash, ...) -> enrich-
export const ENTITY_TYPE_WORK = 'work';

export const workToExportFile = (work) => {
  return {
    id: work.internal_id,
    name: work.name || 'Unknown',
    size: 0,
    lastModified: moment(work.updated_at).toDate(),
    lastModifiedSinceMin: sinceNowInMinutes(work.updated_at),
    uploadStatus: work.status,
    metaData: {
      messages: work.messages,
      errors: work.errors,
    },
  };
};

export const connectorForWork = async (id) => {
  const work = await elLoadByIds(id, ENTITY_TYPE_WORK, INDEX_HISTORY);
  if (work) return loadConnectorById(work.connector_id);
  return null;
};

export const findAll = (args = {}) => {
  const finalArgs = R.pipe(
    R.assoc('type', ENTITY_TYPE_WORK),
    R.assoc('orderBy', args.orderBy || 'timestamp'),
    R.assoc('orderMode', args.orderMode || 'desc')
  )(args);
  return elPaginate(INDEX_HISTORY, finalArgs);
};

export const worksForConnector = async (connectorId, args = {}) => {
  const { first = 10, filters = [] } = args;
  filters.push({ key: 'connector_id', values: [connectorId] });
  return elPaginate(INDEX_HISTORY, {
    type: ENTITY_TYPE_WORK,
    connectionFormat: false,
    orderBy: 'timestamp',
    orderMode: 'desc',
    first,
    filters,
  });
};

export const worksForSource = async (sourceId, args = {}) => {
  const { first = 10, filters = [], type } = args;
  const basicFilters = [{ key: 'event_source_id', values: [sourceId] }];
  if (type) basicFilters.push({ key: 'event_type', values: [type] });
  return elPaginate(INDEX_HISTORY, {
    type: ENTITY_TYPE_WORK,
    connectionFormat: false,
    orderBy: 'timestamp',
    orderMode: 'desc',
    first,
    filters: [...basicFilters, ...filters],
  });
};

export const loadExportWorksAsProgressFiles = async (sourceId) => {
  const works = await worksForSource(sourceId, { type: CONNECTOR_INTERNAL_EXPORT_FILE, first: 10 });
  const filterSuccessCompleted = R.filter((w) => w.status !== 'complete' || w.errors.length > 0, works);
  return R.map((item) => workToExportFile(item), filterSuccessCompleted);
};

export const deleteWork = async (workId) => {
  await elDeleteInstanceIds([workId], [INDEX_HISTORY]);
  return workId;
};

export const deleteWorkForFile = async (fileId) => {
  const works = await worksForSource(fileId);
  await Promise.all(R.map((w) => deleteWork(w.internal_id), works));
  return true;
};

const loadWorkById = async (workId) => {
  const action = await elLoadByIds(workId, ENTITY_TYPE_WORK, INDEX_HISTORY);
  return R.assoc('id', workId, action);
};

const deleteOldCompletedWorks = async (sourceId, connectorType) => {
  let numberToKeep = 50;
  if (connectorType === CONNECTOR_INTERNAL_EXPORT_FILE) numberToKeep = 5;
  if (connectorType === CONNECTOR_INTERNAL_IMPORT_FILE) numberToKeep = 5;
  if (connectorType === CONNECTOR_INTERNAL_ENRICHMENT) numberToKeep = 5;
  const query = {
    bool: {
      must: [
        { match_phrase: { 'event_source_id.keyword': sourceId } },
        { match_phrase: { 'status.keyword': 'complete' } },
      ],
    },
  };
  const worksToDelete = await el.search({
    index: INDEX_HISTORY,
    body: {
      query,
      from: numberToKeep - 1,
      sort: [{ completed_time: { order: 'desc', unmapped_type: 'date' } }],
    },
  });
  const { hits } = worksToDelete.body.hits;
  // eslint-disable-next-line no-underscore-dangle
  const ids = hits.map((h) => h._id);
  if (ids.length > 0) {
    await elDeleteInstanceIds(ids, INDEX_HISTORY);
  }
};
export const createWork = async (user, connector, friendlyName, sourceId, args = {}) => {
  // 01. Cleanup complete work older
  await deleteOldCompletedWorks(sourceId, connector.connector_type);
  // 02. Create the new work
  const { receivedTime = null } = args;
  // Create the work and a initial job
  const workId = generateWorkId();
  await elIndex(INDEX_HISTORY, {
    internal_id: workId,
    timestamp: now(),
    name: friendlyName,
    entity_type: ENTITY_TYPE_WORK,
    // For specific type, specific id is required
    event_type: connector.connector_type,
    event_source_id: sourceId,
    // Users
    user_id: user.id, // User asking for the action
    connector_id: connector.id, // Connector responsible for the action
    // Action context
    status: receivedTime ? 'progress' : 'wait', // Wait / Progress / Complete
    received_time: receivedTime,
    processed_time: null,
    completed_time: null,
    messages: [],
    errors: [],
    // Importing sequences
    import_expected_number: 0,
    import_processed_number: 0,
    import_last_processed: null,
  });
  return loadWorkById(workId);
};

export const reportActionImport = (user, workId, errorData) => {
  const params = { now: now() };
  let sourceScript = "ctx._source['import_processed_number'] += 1;";
  sourceScript += "ctx._source['import_last_processed'] = params.now;";
  sourceScript +=
    "if (ctx._source['processed_time'] != null && ctx._source['import_expected_number'] == ctx._source['import_processed_number']) { " +
    /*--*/ 'ctx._source[\'status\'] = "complete";' +
    /*--*/ "ctx._source['completed_time'] = params.now;" +
    '}';
  if (errorData) {
    const { error, source } = errorData;
    sourceScript += `ctx._source.errors.add(["timestamp": params.now, "message": params.error, "source": params.source]); `;
    params.source = source;
    params.error = error;
  }
  return elUpdate(INDEX_HISTORY, workId, {
    script: { source: sourceScript, lang: 'painless', params },
  }).then(() => loadWorkById(workId));
};

export const updateActionExpectation = (user, workId, expectation) => {
  const params = { now: now(), expectation };
  let source = "ctx._source['import_expected_number'] += params.expectation;";
  source +=
    "if (ctx._source['import_expected_number'] == ctx._source['import_processed_number']) { " +
    /*--*/ 'ctx._source[\'status\'] = "complete";' +
    /*--*/ "ctx._source['completed_time'] = params.now;" +
    '} else {' +
    /*--*/ 'ctx._source[\'status\'] = "progress";' +
    /*--*/ "ctx._source['completed_time'] = null;" +
    '}';
  return elUpdate(INDEX_HISTORY, workId, {
    script: { source, lang: 'painless', params },
  }).then(() => loadWorkById(workId));
};

export const updateReceivedTime = (user, workId, message) => {
  const params = { received_time: now(), message };
  let source = 'ctx._source.status = "progress";';
  source += 'ctx._source["received_time"] = params.received_time;';
  if (isNotEmptyField(message)) {
    source += `ctx._source.messages.add(["timestamp": params.received_time, "message": params.message]); `;
  }
  return elUpdate(INDEX_HISTORY, workId, {
    script: { source, lang: 'painless', params },
  }).then(() => loadWorkById(workId));
};

export const updateProcessedTime = (user, workId, message, inError = false) => {
  const params = { processed_time: now(), message };
  let source = 'ctx._source["processed_time"] = params.processed_time;';
  source +=
    "if (ctx._source['import_expected_number'] == ctx._source['import_processed_number']) { " +
    /*--*/ 'ctx._source[\'status\'] = "complete";' +
    /*--*/ "ctx._source['completed_time'] = params.processed_time;" +
    '} else {' +
    /*--*/ 'ctx._source[\'status\'] = "progress";' +
    /*--*/ "ctx._source['completed_time'] = null;" +
    '}';
  if (isNotEmptyField(message)) {
    if (inError) {
      source += `ctx._source.errors.add(["timestamp": params.processed_time, "message": params.message]); `;
    } else {
      source += `ctx._source.messages.add(["timestamp": params.processed_time, "message": params.message]); `;
    }
  }
  return elUpdate(INDEX_HISTORY, workId, {
    script: { source, lang: 'painless', params },
  }).then(() => loadWorkById(workId));
};
