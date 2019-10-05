import uuid from 'uuid/v4';
import { map } from 'ramda';
import {
  commitWriteTx,
  escapeString,
  find,
  load,
  now,
  sinceNowInMinutes,
  takeWriteTx,
  updateAttribute
} from '../database/grakn';
import { CONNECTOR_INTERNAL_EXPORT_FILE } from './connector';

const WORK_STATUS_ERROR = 'error';
const WORK_STATUS_PROGRESS = 'inProgress';

export const workToExportFile = (work, connector) => {
  return {
    id: work.internal_id,
    name: `${connector.created_at}-${connector.name}`,
    size: 0,
    information: `${connector.name}: ${work.work_message}`,
    lastModified: work.updated_at,
    lastModifiedSinceMin: sinceNowInMinutes(work.updated_at),
    uploadStatus: work.work_status,
    metaData: {
      category: 'export'
    }
  };
};

export const loadWork = id => {
  const query = `match $job (work: $work, connector: $connector, carried: $carried) isa job; 
       $work has internal_id "${escapeString(id)}"; get;`;
  return load(query, ['work', 'connector', 'carried']);
};

export const loadEntityWorks = entityId => {
  const query = `match $job (work: $work, connector: $connector, carried: $carried) isa job; 
       $carried has internal_id "${escapeString(entityId)}"; get;`;
  return find(query, ['work', 'connector']);
};

export const loadExportWorksAsProgressFiles = async entityId => {
  const query = `match $job (work: $work, connector: $connector, carried: $carried) isa job; 
       $carried has internal_id "${escapeString(entityId)}"; 
       $work has work_type "${CONNECTOR_INTERNAL_EXPORT_FILE}"; get;`;
  const works = await find(query, ['work', 'connector']);
  return map(item => workToExportFile(item.work, item.connector), works);
};

export const createWork = async (connId, workType, entityId, message = '-') => {
  // Start transaction
  const wTx = await takeWriteTx();
  const internalId = uuid();
  const creation = now();
  // Create the work
  const query = `insert $work isa Work, 
  has internal_id "${internalId}",
  has work_type "${workType}",
  has work_message "${message}",
  has work_status "${WORK_STATUS_PROGRESS}",
  has created_at ${creation},
  has updated_at ${creation};`;
  const exportIterator = await wTx.tx.query(query);
  // Link the work to a connector and an concept
  const createdExport = await exportIterator.next();
  const internalWorkId = await createdExport.map().get('work').id;
  await wTx.tx.query(
    `match $work id ${internalWorkId}; 
     $connector has internal_id "${escapeString(connId)}"; 
     $carried has internal_id "${escapeString(entityId)}"; 
     insert (carried: $carried, connector: $connector, work: $work) isa job, has internal_id "${uuid()}";`
  );
  await commitWriteTx(wTx);
  return loadWork(internalId);
};

export const reportJobError = async (workId, message) => {
  const wTx = await takeWriteTx();
  const messageInput = { key: 'work_message', value: [message] };
  await updateAttribute(workId, messageInput, wTx);
  const statusInput = { key: 'work_status', value: [WORK_STATUS_ERROR] };
  await updateAttribute(workId, statusInput, wTx);
  await commitWriteTx(wTx);
  return true;
};
