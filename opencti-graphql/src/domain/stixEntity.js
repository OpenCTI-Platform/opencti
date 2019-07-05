import { send } from '../database/rabbitmq';

export const importData = async (type, file) => {
  send(
    'opencti',
    type,
    JSON.stringify({
      type,
      file_name: file.name,
      content: file.base64
    })
  );
  return true;
};
