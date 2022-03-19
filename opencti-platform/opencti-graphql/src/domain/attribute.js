import { elAttributeValues, elUpdateAttributeValue } from '../database/engine';
import { queryAttributes } from '../database/middleware';

export const getRuntimeAttributeValues = (user, opts = {}) => {
  const { attributeName } = opts;
  return elAttributeValues(user, attributeName, opts);
};

export const getSchemaAttributeValues = (elementType) => {
  return queryAttributes(elementType);
};

export const attributeEditField = async ({ id, previous, current }) => {
  await elUpdateAttributeValue(id, previous, current);
  return id;
};
