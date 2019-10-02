import { upload } from '../database/minio';
import { send } from '../database/rabbitmq';
import {
  KEY_IMPORT,
  RABBITMQ_EXCHANGE_NAME,
  RABBITMQ_IMPORT_ROUTING_KEY
} from '../config/conf';

// eslint-disable-next-line
export const uploadImport = async ({ file, entityId }, user) => {
  const up = await upload(user, 'import', file, entityId);
  send(
    RABBITMQ_EXCHANGE_NAME,
    RABBITMQ_IMPORT_ROUTING_KEY,
    JSON.stringify({
      type: KEY_IMPORT + up.metaData.mimetype, // Ex. file-import-application/json
      file_path: `/storage/get/${up.id}`
    })
  );
  return up;
};
