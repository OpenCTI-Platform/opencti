import { head } from 'ramda';
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

export const findById = (attributeId) => {
  return loadById(attributeId, ENTITY_TYPE_ATTRIBUTE);
};

export const find = (attributeKey, attributeValue) => {
  const filters = [
    { key: 'key', values: [attributeKey] },
    { key: 'value', values: [attributeValue] },
  ];
  return listEntities([ENTITY_TYPE_ATTRIBUTE], { filters, connectionFormat: false }).then((attributes) =>
    head(attributes)
  );
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
  const attribute = await updateAttribute(user, attributeId, ENTITY_TYPE_ATTRIBUTE, input);
  // TODO JRI
  // Impact all entities using this attribute
  // New attribute is { key: KEY, value: VALUE }
  return notify(BUS_TOPICS[ENTITY_TYPE_ATTRIBUTE].EDIT_TOPIC, attribute, user);
};
