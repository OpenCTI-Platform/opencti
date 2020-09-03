import { assoc } from 'ramda';
import { delEditContext, notify, setEditContext } from '../database/redis';
import { createEntity, deleteEntityById, listEntities, loadById, updateAttribute } from '../database/grakn';
import { BUS_TOPICS } from '../config/conf';
import { ENTITY_TYPE_LABEL } from '../schema/stixMetaObject';

export const findById = (labelId) => {
  return loadById(labelId, ENTITY_TYPE_LABEL);
};

export const findAll = (args) => {
  return listEntities([ENTITY_TYPE_LABEL], ['value'], args);
};

export const stringToColour = (str) => {
  let hash = 0;
  for (let i = 0; i < str.length; i += 1) {
    hash = str.charCodeAt(i) + ((hash << 5) - hash);
  }
  let colour = '#';
  for (let i = 0; i < 3; i += 1) {
    const value = (hash >> (i * 8)) & 0xff;
    colour += `00${value.toString(16)}`.substr(-2);
  }
  return colour;
};

export const addLabel = async (user, label) => {
  const created = await createEntity(
    user,
    assoc('color', label.color ? label.color : stringToColour(label.value), label),
    ENTITY_TYPE_LABEL,
    { noLog: true }
  );
  return notify(BUS_TOPICS[ENTITY_TYPE_LABEL].ADDED_TOPIC, created, user);
};

export const labelDelete = (user, labelId) => deleteEntityById(user, labelId, ENTITY_TYPE_LABEL, { noLog: true });

export const labelEditField = async (user, labelId, input) => {
  const label = await updateAttribute(user, labelId, ENTITY_TYPE_LABEL, input, { noLog: true });
  return notify(BUS_TOPICS[ENTITY_TYPE_LABEL].EDIT_TOPIC, label, user);
};

export const labelCleanContext = async (user, labelId) => {
  await delEditContext(user, labelId);
  return loadById(labelId, ENTITY_TYPE_LABEL).then((label) =>
    notify(BUS_TOPICS[ENTITY_TYPE_LABEL].EDIT_TOPIC, label, user)
  );
};

export const labelEditContext = async (user, labelId, input) => {
  await setEditContext(user, labelId, input);
  return loadById(labelId, ENTITY_TYPE_LABEL).then((label) =>
    notify(BUS_TOPICS[ENTITY_TYPE_LABEL].EDIT_TOPIC, label, user)
  );
};
