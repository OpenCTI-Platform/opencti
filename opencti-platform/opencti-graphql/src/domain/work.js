import uuid from 'uuid/v4';
import { assoc, map } from 'ramda';
import {
  commitWriteTx,
  escapeString,
  find,
  getById,
  load,
  graknNow,
  sinceNowInMinutes,
  takeWriteTx,
  updateAttribute,
  now,
  paginate
} from '../database/grakn';
import { CONNECTOR_INTERNAL_EXPORT_FILE } from './connector';

export const workToExportFile = (work, connector) => {
  return {
    id: work.internal_id,
    name: work.work_file,
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

export const loadConnectorForWork = id => {
  const query = `match $job (work: $work, connector: $connector) isa job; 
       $work has internal_id "${escapeString(id)}"; get;`;
  return load(query, ['connector']).then(data => data.connector);
};

export const workForEntity = async (entityId, args) => {
  return paginate(
    `match $work isa Work; $work has work_entity "${escapeString(entityId)}"`,
    args
  );
};

export const loadFileWorks = async fileId => {
  const query = `match $job (work: $work, connector: $connector) isa job; 
       $work has work_file "${escapeString(fileId)}"; get;`;
  const data = await find(query, ['work', 'connector']);
  return map(d => assoc('connector', d.connector, d.work), data);
};

export const loadExportWorksAsProgressFiles = async entityId => {
  const query = `match $job (work: $work, connector: $connector) isa job; 
       $work has work_status "progress";
       $work has work_entity "${escapeString(entityId)}"; 
       $work has work_type "${CONNECTOR_INTERNAL_EXPORT_FILE}"; get;`;
  const works = await find(query, ['work', 'connector']);
  return map(item => workToExportFile(item.work, item.connector), works);
};

export const createWork = async (connector, entityId = null, fileId = null) => {
  // Start transaction
  const wTx = await takeWriteTx();
  const internalId = uuid();
  const creation = graknNow();
  // Create the work
  const query = `insert $work isa Work, 
  has internal_id "${internalId}",
  has work_entity "${entityId || ''}",
  has work_file "${fileId || ''}",
  has work_type "${connector.connector_type}",
  has work_status "progress",
  has work_message "",
  has created_at ${creation},
  has updated_at ${creation};`;
  const exportIterator = await wTx.tx.query(query);
  // Link the work to a connector and an concept
  const createdExport = await exportIterator.next();
  const internalWorkId = await createdExport.map().get('work').id;
  await wTx.tx.query(
    `match $work id ${internalWorkId}; 
     $connector has internal_id "${escapeString(connector.internal_id)}"; 
     insert (connector: $connector, work: $work) isa job, has internal_id "${uuid()}";`
  );
  await commitWriteTx(wTx);
  return getById(internalId, true);
};

export const reportJobStatus = async (workId, status, message) => {
  const wTx = await takeWriteTx();
  const messageInput = { key: 'work_message', value: [message] };
  await updateAttribute(workId, messageInput, wTx);
  const statusInput = { key: 'work_status', value: [status] };
  await updateAttribute(workId, statusInput, wTx);
  const updateInput = { key: 'updated_at', value: [now()] };
  await updateAttribute(workId, updateInput, wTx);
  await commitWriteTx(wTx);
  return getById(workId, true);
};
