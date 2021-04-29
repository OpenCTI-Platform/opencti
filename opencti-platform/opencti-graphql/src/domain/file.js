import * as R from 'ramda';
import { loadFile, upload } from '../database/minio';
import { pushToConnector } from '../database/rabbitmq';
import { connectorsForImport } from './connector';
import { createWork } from './work';
import { logApp } from '../config/conf';

export const uploadJobImport = async (user, fileId, fileMime, entityId, manual = false, connectorId = null) => {
  let connectors = await connectorsForImport(user, fileMime, true, !manual);
  if (connectorId) {
    connectors = R.filter((n) => n.id === connectorId, connectors);
  }
  if (!entityId) {
    connectors = R.filter((n) => !n.only_contextual, connectors);
  }
  if (connectors.length > 0) {
    // Create job and send ask to broker
    const createConnectorWork = async (connector) => {
      const work = await createWork(user, connector, 'Manual import', fileId);
      return { connector, work };
    };
    const actionList = await Promise.all(R.map((connector) => createConnectorWork(connector), connectors));
    // Send message to all correct connectors queues
    const buildConnectorMessage = (data) => {
      const { work } = data;
      return {
        internal: {
          work_id: work.id, // Related action for history
          applicant_id: user.id, // User asking for the import
        },
        event: {
          file_id: fileId,
          file_mime: fileMime,
          file_fetch: `/storage/get/${fileId}`, // Path to get the file
          entity_id: entityId, // Context of the upload
        },
      };
    };
    const pushMessage = (data) => {
      const { connector } = data;
      const message = buildConnectorMessage(data);
      return pushToConnector(connector, message);
    };
    await Promise.all(R.map((data) => pushMessage(data), actionList));
  }
};

export const askJobImport = async (user, args) => {
  const { fileName, connectorId = null } = args;
  logApp.debug(`[JOBS] ask import for file ${fileName} by ${user.user_email}`);
  const file = await loadFile(user, fileName);
  await uploadJobImport(user, file.id, file.metaData.mimetype, file.metaData.entity_id, true, connectorId);
  return file;
};

export const uploadImport = async (user, file) => {
  const up = await upload(user, 'import/global', file);
  await uploadJobImport(user, up.id, up.metaData.mimetype, up.metaData.entity_id);
  return up;
};
