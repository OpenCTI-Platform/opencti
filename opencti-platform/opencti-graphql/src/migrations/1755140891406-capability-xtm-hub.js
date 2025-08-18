import { logMigration } from '../config/conf';
import { loadEntity } from '../database/middleware';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { ENTITY_TYPE_CAPABILITY } from '../schema/internalObject';
import { addCapability, updateCapability } from '../domain/grant';
import { isNotEmptyField } from '../database/utils';

const message = '[MIGRATION] Add XTM Hub Capability';

export const up = async (next) => {
  logMigration.info(`${message} > started`);
  const context = executionContext('migration');
  const capability = await loadEntity(context, SYSTEM_USER, [ENTITY_TYPE_CAPABILITY], {
    filters: {
      mode: 'and',
      filters: [{ key: 'name', values: ['SETTINGS_SETMANAGEXTMHUB'] }],
      filterGroups: [],
    }
  });
  if (isNotEmptyField(capability)) {
    await updateCapability(context, SYSTEM_USER, capability.id, [{ key: 'attribute_order', value: [3450] }]);
  } else {
    await addCapability(context, SYSTEM_USER, {
      name: 'SETTINGS_SETMANAGEXTMHUB',
      description: 'Manage XTM Hub',
      attribute_order: 3450
    });
  }
  logMigration.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
