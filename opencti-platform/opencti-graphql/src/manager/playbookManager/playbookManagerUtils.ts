interface EventConfig {
  create?: boolean
  update?: boolean
  delete?: boolean
}

export const isValidEventType = (eventType: string, configuration: EventConfig) => {
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
