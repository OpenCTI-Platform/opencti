import * as R from 'ramda';
import {
  loadById,
  listEntities,
  createEntity,
  deleteElementById,
  updateAttribute,
  queryAttributes,
  loadEntity,
} from '../database/middleware';
import { ENTITY_TYPE_ATTRIBUTE } from '../schema/internalObject';
import { notify } from '../database/redis';
import { BUS_TOPICS } from '../config/conf';
import { elUpdateAttributeValue } from '../database/elasticSearch';

export const findById = (attributeId) => {
  return loadById(attributeId, ENTITY_TYPE_ATTRIBUTE);
};

export const find = (attributeKey, attributeValue) => {
  const filters = [
    { key: 'key', values: [attributeKey] },
    { key: 'value', values: [attributeValue] },
  ];
  return loadEntity([ENTITY_TYPE_ATTRIBUTE], { filters });
};

export const findAll = (args) => {
  if (args.elementType) {
    return queryAttributes(args.elementType);
  }
  const filters = [];
  if (args.key) {
    filters.push({ key: 'key', values: [args.key] });
  }
  return listEntities([ENTITY_TYPE_ATTRIBUTE], R.pipe(R.assoc('filters', filters), R.dissoc('key'))(args));
};

export const addAttribute = async (user, attribute) => {
  const created = await createEntity(user, attribute, ENTITY_TYPE_ATTRIBUTE);
  return notify(BUS_TOPICS[ENTITY_TYPE_ATTRIBUTE].ADDED_TOPIC, created, user);
};

export const attributeDelete = (user, attributeId) => deleteElementById(user, attributeId, ENTITY_TYPE_ATTRIBUTE);

export const attributeEditField = async (user, attributeId, input) => {
  const previous = await loadById(attributeId, ENTITY_TYPE_ATTRIBUTE);
  const { value } = input;
  await elUpdateAttributeValue(previous.key, previous.value, R.head(value));
  const attribute = await updateAttribute(user, attributeId, ENTITY_TYPE_ATTRIBUTE, input);
  return notify(BUS_TOPICS[ENTITY_TYPE_ATTRIBUTE].EDIT_TOPIC, attribute, user);
};
