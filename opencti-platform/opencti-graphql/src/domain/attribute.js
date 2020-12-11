import {
  loadById,
  listEntities,
  createEntity,
  deleteElementById,
  updateAttribute,
  queryAttributes,
} from '../database/grakn';
import { ENTITY_TYPE_ATTRIBUTE } from '../schema/internalObject';
import { notify } from '../database/redis';
import { BUS_TOPICS } from '../config/conf';
import { elUpdateAttributeValue } from '../database/elasticSearch';

export const findById = (attributeId) => {
  return loadById(attributeId, ENTITY_TYPE_ATTRIBUTE);
};

export const find = (attributeKey, attributeValue = null) => {
  const filters = [{ key: [attributeKey] }];
  if (attributeValue) {
    filters.push({ value: [attributeValue] });
  }
  return listEntities([ENTITY_TYPE_ATTRIBUTE], { filters });
};

export const findAll = (args) => {
  if (args.elementType) {
    return queryAttributes(args.elementType);
  }
  return listEntities([ENTITY_TYPE_ATTRIBUTE], args);
};

export const addAttribute = async (user, attribute) => {
  const created = await createEntity(user, attribute, ENTITY_TYPE_ATTRIBUTE);
  return notify(BUS_TOPICS[ENTITY_TYPE_ATTRIBUTE].ADDED_TOPIC, created, user);
};

export const attributeDelete = (user, attributeId) => deleteElementById(user, attributeId, ENTITY_TYPE_ATTRIBUTE);

export const attributeEditField = async (user, attributeId, input) => {
  const previous = await loadById(attributeId, ENTITY_TYPE_ATTRIBUTE);
  const attribute = await updateAttribute(user, attributeId, ENTITY_TYPE_ATTRIBUTE, input);
  const { key, value } = attribute;
  await elUpdateAttributeValue(key, previous.value, value);
  return notify(BUS_TOPICS[ENTITY_TYPE_ATTRIBUTE].EDIT_TOPIC, attribute, user);
};
