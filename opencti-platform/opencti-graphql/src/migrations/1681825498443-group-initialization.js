import { executionContext, SYSTEM_USER } from '../utils/access';
import { logApp } from '../config/conf';
import { groupEditField } from '../domain/group';
import { ENTITY_TYPE_GROUP } from '../schema/internalObject';
import { listAllEntities } from '../database/middleware-loader';

export const up = async (next) => {
  const context = executionContext('migration');
  const groups = await listAllEntities(context, SYSTEM_USER, [ENTITY_TYPE_GROUP]);
  const groupEditionPromises = groups.map((group) => {
    const updateInput = [];
    if (group.auto_new_marking === undefined) {
      updateInput.push({ key: 'auto_new_marking', value: ['false'] });
    }
    if (group.default_assignation === undefined) {
      updateInput.push({ key: 'default_assignation', value: ['false'] });
    }
    return updateInput.length > 0 ? groupEditField(context, SYSTEM_USER, group.id, updateInput) : null;
  }).filter((promise) => promise !== null);
  await Promise.all(groupEditionPromises);
  logApp.info('[MIGRATION] Refacto group initialization done.');
  next();
};

export const down = async (next) => {
  next();
};
