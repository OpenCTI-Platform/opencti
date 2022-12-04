import { elAttributeValues, elUpdateAttributeValue } from '../database/engine';
import { queryAttributes } from '../database/middleware';

export const getRuntimeAttributeValues = (context, user, opts = {}) => {
  const { attributeName } = opts;
  return elAttributeValues(context, user, attributeName, opts);
};

export const getSchemaAttributeValues = (elementTypes) => {
  return queryAttributes(elementTypes);
};

export const attributeEditField = async (context, { id, previous, current }) => {
  await elUpdateAttributeValue(context, id, previous, current);
  return id;
};
