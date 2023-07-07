import { Promise } from 'bluebird';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { logApp } from '../config/conf';
import { groupEditField } from '../domain/group';
import { ENTITY_TYPE_GROUP } from '../schema/internalObject';
import { listAllEntities } from '../database/middleware-loader';
import { ES_MAX_CONCURRENCY } from '../database/engine';

export const up = async (next) => {
  logApp.info('[MIGRATION] Group initialization migration');
  const context = executionContext('migration');
  const groups = await listAllEntities(context, SYSTEM_USER, [ENTITY_TYPE_GROUP]);
  const patchingGroups = groups.filter((g) => g.auto_new_marking === undefined || g.default_assignation === undefined);
  logApp.info(`[MIGRATION] Group initialization patching ${patchingGroups.length} groups`);
  let currentProcessing = 0;
  const concurrentUpdate = async (group) => {
    const updateInput = [];
    if (group.auto_new_marking === undefined) {
      updateInput.push({ key: 'auto_new_marking', value: ['false'] });
    }
    if (group.default_assignation === undefined) {
      updateInput.push({ key: 'default_assignation', value: ['false'] });
    }
    await groupEditField(context, SYSTEM_USER, group.id, updateInput);
    currentProcessing += 1;
    logApp.info(`[OPENCTI] Group initialization patching : ${currentProcessing} / ${patchingGroups.length}`);
  };
  await Promise.map(patchingGroups, concurrentUpdate, { concurrency: ES_MAX_CONCURRENCY });
  logApp.info('[MIGRATION] Group initialization done.');
  next();
};

export const down = async (next) => {
  next();
};
