import { send } from '../database/rabbitmq';
import {
  RABBITMQ_EXCHANGE_NAME,
  RABBITMQ_IMPORT_ROUTING_KEY
} from '../config/conf';

// eslint-disable-next-line
export const importData = async (type, file) => {
  send(
    RABBITMQ_EXCHANGE_NAME,
    RABBITMQ_IMPORT_ROUTING_KEY,
    JSON.stringify({
      type,
      file_name: file.name,
      content: file.base64
    })
  );
  return true;
};
