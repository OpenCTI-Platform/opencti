import moment from 'moment';
import * as R from 'ramda';
import {
  el,
  elDeleteInstanceIds,
  elIndex,
  elLoadByIds,
  elPaginate,
  elUpdate,
  ES_IGNORE_THROTTLED,
} from '../database/elasticSearch';
import { CONNECTOR_INTERNAL_ENRICHMENT, CONNECTOR_INTERNAL_EXPORT_FILE, loadConnectorById } from './connector';
import { generateWorkId } from '../schema/identifier';
import { READ_INDEX_HISTORY, isNotEmptyField, INDEX_HISTORY } from '../database/utils';
import { redisCreateWork, redisDeleteWork, redisGetWork, redisUpdateWorkFigures } from '../database/redis';
import { logApp } from '../config/conf';
import { ENTITY_TYPE_WORK } from '../schema/internalObject';
import { DatabaseError } from '../config/errors';
import { now, sinceNowInMinutes } from '../utils/format';

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

export const connectorForWork = async (user, id) => {
  const work = await elLoadByIds(user, id, ENTITY_TYPE_WORK, READ_INDEX_HISTORY);
  if (work) return loadConnectorById(user, work.connector_id);
  return null;
};

export const findAll = (user, args = {}) => {
  const finalArgs = R.pipe(
    R.assoc('type', ENTITY_TYPE_WORK),
    R.assoc('orderBy', args.orderBy || 'timestamp'),
    R.assoc('orderMode', args.orderMode || 'desc')
  )(args);
  return elPaginate(user, READ_INDEX_HISTORY, finalArgs);
};

export const worksForConnector = async (connectorId, user, args = {}) => {
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

const loadWorkById = async (user, workId) => {
  const action = await elLoadByIds(user, workId, ENTITY_TYPE_WORK, READ_INDEX_HISTORY);
  return R.assoc('id', workId, action);
};

export const deleteWorkRaw = async (work) => {
  await elDeleteInstanceIds([work]);
  await redisDeleteWork(work.internal_id);
  return work.internal_id;
};

export const deleteWork = async (user, workId) => {
  const work = await loadWorkById(user, workId);
  return deleteWorkRaw(work);
};

export const deleteWorkForFile = async (user, fileId) => {
  const works = await worksForSource(user, fileId);
  await Promise.all(R.map((w) => deleteWorkRaw(w), works));
  return true;
};

export const deleteOldCompletedWorks = async (connector, logInfo = false) => {
  const paginationCount = 500;
  const rangeToKeep = connector.connector_type === CONNECTOR_INTERNAL_ENRICHMENT ? 'now-2d/d' : 'now-30d/d';
  const query = {
    bool: {
      must: [
        { match_phrase: { 'connector_id.keyword': connector.id } },
        { match_phrase: { 'status.keyword': 'complete' } },
        { range: { completed_time: { lte: rangeToKeep } } },
      ],
    },
  };
  let counter = 0;
  let hasNextPage = true;
  let searchAfter = '';
  let totalToDelete = null;
  while (hasNextPage) {
    let body = {
      query,
      size: paginationCount,
      track_total_hits: true,
      sort: [{ completed_time: { order: 'desc', unmapped_type: 'date' } }],
    };
    if (searchAfter) {
      body = { ...body, search_after: [searchAfter] };
    }
    const worksToDelete = await el
      .search({ index: READ_INDEX_HISTORY, ignore_throttled: ES_IGNORE_THROTTLED, body })
      .catch((e) => {
        throw DatabaseError('Error searching for works to delete', { error: e });
      });
    // eslint-disable-next-line prettier/prettier
    const {
      hits,
      total: { value: valTotal },
    } = worksToDelete.body.hits;
    if (totalToDelete === null) totalToDelete = valTotal;
    if (hits.length === 0) {
      hasNextPage = false;
    } else {
      const lastHit = R.last(hits);
      counter += hits.length;
      searchAfter = R.head(lastHit.sort);
      if (hits.length > 0) {
        const works = hits.map((h) => R.assoc('_index', h._index, h._source));
        const ids = works.map((w) => w.internal_id);
        await redisDeleteWork(ids);
        await elDeleteInstanceIds(works);
      }
      if (logInfo) {
        const message = `[WORKS] Deleting old works ${connector.name}: ${counter}/${totalToDelete}`;
        logApp.info(message);
      }
    }
  }
};

export const createWork = async (user, connector, friendlyName, sourceId, args = {}) => {
  // 01. Cleanup complete work older
  await deleteOldCompletedWorks(connector);
  // 02. Create the new work
  const { receivedTime = null } = args;
  // Create the work and a initial job
  const workId = generateWorkId();
  const work = {
    internal_id: workId,
    timestamp: now(),
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
    received_time: receivedTime,
    processed_time: null,
    completed_time: null,
    completed_number: 0,
    messages: [],
    errors: [],
  };
  const workTracing = {
    internal_id: workId,
    import_expected_number: 0,
    import_processed_number: 0,
  };
  await redisCreateWork(workTracing);
  await elIndex(INDEX_HISTORY, work);
  return loadWorkById(user, workId);
};

const isWorkCompleted = async (workId) => {
  const { import_processed_number: pn, import_expected_number: en } = await redisGetWork(workId);
  // eslint-disable-next-line camelcase
  return { isComplete: parseInt(pn, 10) === parseInt(en, 10), total: pn };
};

export const reportActionImport = async (user, workId, errorData) => {
  const timestamp = now();
  const { isComplete, total } = await redisUpdateWorkFigures(workId);
  // const { isComplete, total } = await isWorkCompleted(workId);
  if (isComplete || errorData) {
    const params = { now: timestamp };
    let sourceScript = '';
    if (isComplete) {
      params.completed_number = total;
      sourceScript += `ctx._source['status'] = "complete"; 
      ctx._source['completed_number'] = params.completed_number;
      ctx._source['completed_time'] = params.now;`;
    }
    if (errorData) {
      const { error, source } = errorData;
      sourceScript += `ctx._source.errors.add(["timestamp": params.now, "message": params.error, "source": params.source]); `;
      params.source = source;
      params.error = error;
    }
    await elUpdate(INDEX_HISTORY, workId, {
      script: { source: sourceScript, lang: 'painless', params },
    });
  }
  return workId;
};

export const updateReceivedTime = async (user, workId, message) => {
  const params = { received_time: now(), message };
  let source = 'ctx._source.status = "progress";';
  source += 'ctx._source["received_time"] = params.received_time;';
  if (isNotEmptyField(message)) {
    source += `ctx._source.messages.add(["timestamp": params.received_time, "message": params.message]); `;
  }
  await elUpdate(INDEX_HISTORY, workId, {
    script: { source, lang: 'painless', params },
  });
  return workId;
};

export const updateProcessedTime = async (user, workId, message, inError = false) => {
  const params = { processed_time: now(), message };
  let source = 'ctx._source["processed_time"] = params.processed_time;';
  const { isComplete, total } = await isWorkCompleted(workId);
  if (isComplete) {
    params.completed_number = total;
    source += `ctx._source['status'] = "complete"; 
               ctx._source['completed_number'] = params.completed_number;
               ctx._source['completed_time'] = params.processed_time;`;
  }
  if (isNotEmptyField(message)) {
    if (inError) {
      source += `ctx._source.errors.add(["timestamp": params.processed_time, "message": params.message]); `;
    } else {
      source += `ctx._source.messages.add(["timestamp": params.processed_time, "message": params.message]); `;
    }
  }
  await elUpdate(INDEX_HISTORY, workId, {
    script: { source, lang: 'painless', params },
  });
  return workId;
};
