import type { StreamConfiguration } from '../../modules/playbook/playbook-components';

export const isValidEventType = (eventType: string, configuration: StreamConfiguration) => {
  const {
    update,
    create,
    delete: deletion
  } = configuration;

  let validEventType = false;
  if (eventType === 'create' && create === true) validEventType = true;
  if (eventType === 'update' && update === true) validEventType = true;
  if (eventType === 'delete' && deletion === true) validEventType = true;

  return validEventType;
};
