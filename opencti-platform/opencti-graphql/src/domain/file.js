import { map } from 'ramda';
import { loadFile, upload } from '../database/minio';
import { pushToConnector } from '../database/rabbitmq';
import { connectorsForImport } from './connector';
import { createWork } from './work';
import { logger } from '../config/conf';
import { internalLoadById } from '../database/middleware';
import { isStixDomainObjectContainer } from '../schema/stixDomainObject';
import { UnsupportedError } from '../config/errors';

const uploadJobImport = async (user, fileId, fileMime, entityId) => {
  let isImportInContainer = false;
  if (entityId) {
    const entity = await internalLoadById(entityId);
    isImportInContainer = isStixDomainObjectContainer(entity.entity_type);
    if (!isImportInContainer) throw UnsupportedError('Cant importing on none container entity');
  }
  const connectors = await connectorsForImport(fileMime, true);
  if (connectors.length > 0) {
    // Create job and send ask to broker
    const createConnectorWork = async (connector) => {
      const work = await createWork(user, connector, 'Manual import', fileId);
      return { connector, work };
    };
    const actionList = await Promise.all(map((connector) => createConnectorWork(connector), connectors));
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
          container_id: isImportInContainer ? entityId : null, // Can be report, Note, ...
        },
      };
    };
    const pushMessage = (data) => {
      const { connector } = data;
      const message = buildConnectorMessage(data);
      return pushToConnector(connector, message);
    };
    await Promise.all(map((data) => pushMessage(data), actionList));
  }
};

export const askJobImport = async (user, filename) => {
  logger.debug(`[JOBS] ask import for file ${filename} by ${user.user_email}`);
  const file = await loadFile(filename);
  await uploadJobImport(user, file.id, file.metaData.mimetype, file.metaData.entity_id);
  return file;
};

export const uploadImport = async (user, file) => {
  const up = await upload(user, 'import/global', file);
  await uploadJobImport(user, up.id, up.metaData.mimetype, up.metaData.entity_id);
  return up;
};
