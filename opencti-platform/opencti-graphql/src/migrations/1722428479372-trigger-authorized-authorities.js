import { logApp } from '../config/conf';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { elList, elReplace } from '../database/engine';
import { READ_INDEX_INTERNAL_OBJECTS } from '../database/utils';
import { ENTITY_TYPE_TRIGGER } from '../modules/notification/notification-types';

const message = '[MIGRATION] update authorized authorities for triggers';

export const up = async (next) => {
  logApp.info(`${message} > started`);
  const context = executionContext('migration');

  // ------ Update triggers
  const callback = async (notifiers) => {
    for (let i = 0; i < notifiers.length; i += 1) {
      const notifier = notifiers[i];
      const patch = { authorized_authorities: ['SETTINGS_SECURITYACTIVITY'] };
      await elReplace(notifier._index, notifier.internal_id, { doc: patch });
    }
  };
  const opts = { types: [ENTITY_TYPE_TRIGGER], callback };
  await elList(context, SYSTEM_USER, READ_INDEX_INTERNAL_OBJECTS, opts);

  logApp.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
