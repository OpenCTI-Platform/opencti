import * as R from 'ramda';
import {
  loadById,
  createEntity,
  deleteElementById,
  updateAttribute,
  queryAttributes,
  loadEntity,
} from '../database/middleware';
import { ENTITY_TYPE_ATTRIBUTE } from '../schema/internalObject';
import { notify } from '../database/redis';
import { BUS_TOPICS } from '../config/conf';
import { elAttributeValues, elUpdateAttributeValue } from '../database/engine';
import { listEntities } from '../database/repository';

export const findById = (user, attributeId) => {
  return loadById(user, attributeId, ENTITY_TYPE_ATTRIBUTE);
};

export const find = (user, attributeKey, attributeValue) => {
  const filters = [
    { key: 'key', values: [attributeKey] },
    { key: 'value', values: [attributeValue] },
  ];
  return loadEntity(user, [ENTITY_TYPE_ATTRIBUTE], { filters });
};

export const findAll = (user, args) => {
  if (args.fieldKey) {
    return elAttributeValues(user, args.fieldKey);
  }
  if (args.elementType) {
    return queryAttributes(args.elementType);
  }
  const filters = [];
  if (args.key) {
    filters.push({ key: 'key', values: [args.key] });
  }
  return listEntities(user, [ENTITY_TYPE_ATTRIBUTE], R.pipe(R.assoc('filters', filters), R.dissoc('key'))(args));
};

export const addAttribute = async (user, attribute) => {
  const created = await createEntity(user, attribute, ENTITY_TYPE_ATTRIBUTE);
  return notify(BUS_TOPICS[ENTITY_TYPE_ATTRIBUTE].ADDED_TOPIC, created, user);
};

export const attributeDelete = (user, attributeId) => deleteElementById(user, attributeId, ENTITY_TYPE_ATTRIBUTE);

export const attributeEditField = async (user, attributeId, inputs) => {
  const previous = await loadById(user, attributeId, ENTITY_TYPE_ATTRIBUTE);
  const { value } = R.head(inputs);
  await elUpdateAttributeValue(previous.key, previous.value, R.head(value));
  const { element } = await updateAttribute(user, attributeId, ENTITY_TYPE_ATTRIBUTE, inputs);
  return notify(BUS_TOPICS[ENTITY_TYPE_ATTRIBUTE].EDIT_TOPIC, element, user);
};
