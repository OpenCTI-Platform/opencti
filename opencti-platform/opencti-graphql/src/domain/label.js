import { assoc, pipe } from 'ramda';
import { delEditContext, notify, setEditContext } from '../database/redis';
import { createEntity, deleteElementById, storeLoadById, updateAttribute } from '../database/middleware';
import { listEntities } from '../database/middleware-loader';
import { BUS_TOPICS } from '../config/conf';
import { ENTITY_TYPE_LABEL } from '../schema/stixMetaObject';
import { normalizeName } from '../schema/identifier';

export const findById = (user, labelId) => {
  return storeLoadById(user, labelId, ENTITY_TYPE_LABEL);
};

export const findAll = (user, args) => {
  return listEntities(user, [ENTITY_TYPE_LABEL], args);
};

export const stringToColour = (str) => {
  let hash = 0;
  for (let i = 0; i < str.length; i += 1) {
    // eslint-disable-next-line no-bitwise
    hash = str.charCodeAt(i) + ((hash << 5) - hash);
  }
  let colour = '#';
  for (let i = 0; i < 3; i += 1) {
    // eslint-disable-next-line no-bitwise
    const value = (hash >> (i * 8)) & 0xff;
    colour += `00${value.toString(16)}`.substr(-2);
  }
  return colour;
};

export const addLabel = async (user, label) => {
  const finalLabel = pipe(
    assoc('value', normalizeName(label.value).toLowerCase()),
    assoc('color', label.color ? label.color : stringToColour(normalizeName(label.value)))
  )(label);
  const created = await createEntity(user, finalLabel, ENTITY_TYPE_LABEL);
  return notify(BUS_TOPICS[ENTITY_TYPE_LABEL].ADDED_TOPIC, created, user);
};

export const labelDelete = (user, labelId) => deleteElementById(user, labelId, ENTITY_TYPE_LABEL);

export const labelEditField = async (user, labelId, input, opts = {}) => {
  const { element } = await updateAttribute(user, labelId, ENTITY_TYPE_LABEL, input, opts);
  return notify(BUS_TOPICS[ENTITY_TYPE_LABEL].EDIT_TOPIC, element, user);
};

export const labelCleanContext = async (user, labelId) => {
  await delEditContext(user, labelId);
  return storeLoadById(user, labelId, ENTITY_TYPE_LABEL).then((label) => notify(BUS_TOPICS[ENTITY_TYPE_LABEL].EDIT_TOPIC, label, user));
};

export const labelEditContext = async (user, labelId, input) => {
  await setEditContext(user, labelId, input);
  return storeLoadById(user, labelId, ENTITY_TYPE_LABEL).then((label) => notify(BUS_TOPICS[ENTITY_TYPE_LABEL].EDIT_TOPIC, label, user));
};
