import { v4 as uuid } from 'uuid';
import { assoc, filter, map, pipe } from 'ramda';
import moment from 'moment';
import { now, sinceNowInMinutes } from '../database/grakn';
import { elDeleteByField, elIndex, elLoadById, elPaginate, INDEX_WORK_JOBS } from '../database/elasticSearch';
import { loadConnectorById } from './connector';

// region utils
export const workToExportFile = (work) => {
  return {
    id: work.internal_id_key,
    name: work.work_file,
    size: 0,
    lastModified: moment(work.updated_at).toDate(),
    lastModifiedSinceMin: sinceNowInMinutes(work.updated_at),
    uploadStatus: 'progress',
    metaData: {
      category: 'export',
    },
  };
};
// endregion

export const connectorForWork = async (id) => {
  const work = await elLoadById(id, null, null, INDEX_WORK_JOBS);
  if (work) return loadConnectorById(work.connector_id);
  return null;
};

export const jobsForWork = async (id) => {
  return elPaginate(INDEX_WORK_JOBS, {
    types: ['Job'],
    connectionFormat: false,
    orderBy: 'created_at',
    orderMode: 'asc',
    filters: [{ key: 'work_id', values: [id] }],
  });
};

export const computeWorkStatus = async (id) => {
  const jobs = await jobsForWork(id);
  // Status can be progress / partial / complete
  const isProgress = (job) => job.job_status === 'wait' || job.job_status === 'progress';
  const nbProgress = filter((job) => isProgress(job), jobs).length;
  if (nbProgress > 0) return 'progress';
  const nbErrors = filter((l) => l.job_status === 'error', jobs).length;
  if (nbErrors === jobs.length) return 'error';
  const nbComplete = filter((l) => l.job_status === 'complete', jobs).length;
  if (nbComplete === jobs.length) return 'complete';
  return 'partial';
};

export const workForEntity = async (entityId, args) => {
  return elPaginate(INDEX_WORK_JOBS, {
    type: 'Work',
    connectionFormat: false,
    first: args.first,
    filters: [{ key: 'work_entity', values: [entityId] }],
  });
};

export const workForEntityType = async (entityType, args) => {
  const options = {
    type: 'Work',
    connectionFormat: false,
    first: args.first,
    filters: [{ key: 'work_entity_type', values: [entityType] }],
  };
  if (args.context !== undefined) {
    options.filters.push({ key: 'work_context', values: [args.context] });
  }
  return elPaginate(INDEX_WORK_JOBS, options);
};

export const loadFileWorks = async (fileId) => {
  return elPaginate(INDEX_WORK_JOBS, {
    type: 'Work',
    connectionFormat: false,
    filters: [{ key: 'work_file', values: [fileId] }],
  });
};

export const loadExportWorksAsProgressFiles = async (entityType, entityId, context) => {
  const works = entityId
    ? await workForEntity(entityId, { first: 200 })
    : await workForEntityType(entityType.toLowerCase(), { first: 200, context });
  // Filter if all jobs completed
  const worksWithStatus = await Promise.all(
    map((w) => {
      return computeWorkStatus(w.work_id).then((status) => assoc('status', status, w));
    }, works)
  );
  const onlyProgressWorks = filter((w) => w.status === 'progress', worksWithStatus);
  return map((item) => workToExportFile(item), onlyProgressWorks);
};

export const deleteWork = async (workId) => {
  return elDeleteByField(INDEX_WORK_JOBS, 'work_id', workId);
};

export const deleteWorkForFile = async (fileId) => {
  const works = await loadFileWorks(fileId);
  await Promise.all(map((w) => deleteWork(w.internal_id_key), works));
  return true;
};

export const initiateJob = (workId) => {
  const jobInternalId = uuid();
  return elIndex(INDEX_WORK_JOBS, {
    id: jobInternalId,
    internal_id_key: jobInternalId,
    grakn_id: jobInternalId,
    messages: ['Initiate work'],
    work_id: workId,
    created_at: now(),
    updated_at: now(),
    job_status: 'wait',
    entity_type: 'Job',
  });
};

export const createWork = async (connector, entityType = null, entityId = null, context = null, fileId = null) => {
  // Create the work and a initial job
  const workInternalId = uuid();
  const createdWork = await elIndex(INDEX_WORK_JOBS, {
    id: workInternalId,
    internal_id_key: workInternalId,
    grakn_id: workInternalId,
    work_id: workInternalId,
    entity_type: 'Work',
    connector_id: connector.id,
    work_entity_type: entityType,
    work_entity: entityId,
    work_context: context,
    work_file: fileId,
    work_type: connector.connector_type,
    created_at: now(),
    updated_at: now(),
  });
  const createdJob = await initiateJob(workInternalId);
  return { work: createdWork, job: createdJob };
};

export const updateJob = async (jobId, status, messages) => {
  const job = await elLoadById(jobId, null, null, INDEX_WORK_JOBS);
  const updatedJob = pipe(assoc('job_status', status), assoc('messages', messages), assoc('updated_at', now()))(job);
  await elIndex(INDEX_WORK_JOBS, updatedJob);
  return updatedJob;
};
