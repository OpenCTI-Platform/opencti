import { Promise } from 'bluebird';
import { executionContext, MEMBER_ACCESS_RIGHT_ADMIN, SYSTEM_USER } from '../utils/access';
import { listAllEntities } from '../database/middleware-loader';
import { ENTITY_TYPE_TRIGGER } from '../modules/notification/notification-types';
import { logApp } from '../config/conf';
import { patchAttribute } from '../database/middleware';
import { ES_MAX_CONCURRENCY } from '../database/engine';

export const up = async (next) => {
  logApp.info('[MIGRATION] Triggers add authorizedMembers start');
  const context = executionContext('migration', SYSTEM_USER);
  const triggers = await listAllEntities(context, context.user, [ENTITY_TYPE_TRIGGER]);
  logApp.info(`[MIGRATION] Triggers add authorizedMembers on ${triggers.length} triggers`);
  const updateTriggers = async (trigger) => {
    const triggerUserIds = trigger.user_ids ?? [];
    const authorizedMembersInput = triggerUserIds.map((userId) => {
      return { id: userId, access_right: MEMBER_ACCESS_RIGHT_ADMIN };
    });
    const patch = { authorized_members: authorizedMembersInput };
    await patchAttribute(context, context.user, trigger.id, ENTITY_TYPE_TRIGGER, patch);
  };
  await Promise.map(triggers, updateTriggers, { concurrency: ES_MAX_CONCURRENCY });
  logApp.info('[MIGRATION] Triggers add authorizedMembers done.');
  next();
};

export const down = async (next) => {
  next();
};
