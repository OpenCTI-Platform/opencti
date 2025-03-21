import { logMigration } from '../config/conf';
import { listAllEntities } from '../database/middleware-loader';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { ENTITY_TYPE_ENTITY_SETTING } from '../modules/entitySetting/entitySetting-types';
import { getAttributesConfiguration } from '../modules/entitySetting/entitySetting-utils';
import { authorizedMembers } from '../schema/attribute-definition';
import { elReplace } from '../database/engine';

const message = '[MIGRATION] migrate authorized members default values';

export const up = async (next) => {
  logMigration.info(`${message} > started`);
  // do your migration
  const context = executionContext('migration', SYSTEM_USER);
  const entitySettings = await listAllEntities(context, context.user, [ENTITY_TYPE_ENTITY_SETTING], { connectionFormat: false });
  for (let i = 0; i < entitySettings.length; i += 1) {
    const entitySetting = entitySettings[i];
    let attributesConfiguration = getAttributesConfiguration(entitySetting);
    if (attributesConfiguration && attributesConfiguration.some((attribute) => attribute.name === 'authorized_members')) {
      attributesConfiguration = attributesConfiguration.map((attribute) => {
        if (attribute.name === 'authorized_members') {
          return { ...attribute, name: authorizedMembers.name };
        }
        return attribute;
      });
      const patch = { attributes_configuration: JSON.stringify(attributesConfiguration) };
      logMigration.info(`${message} > replacing attributes configuration for entity setting ${entitySetting.id}`);
      await elReplace(entitySetting._index, entitySetting.id, { doc: patch });
    }
  }
  logMigration.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
