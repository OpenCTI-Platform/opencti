import { executionContext, SYSTEM_USER } from '../utils/access';
import { listAllEntities } from '../database/middleware-loader';
import {
  ENTITY_TYPE_ENTITY_SETTING
} from '../modules/entitySetting/entitySetting-types';
import { entitySettingEditField } from '../modules/entitySetting/entitySetting-domain';
import {
  availableSettings,
  defaultEntitySetting as defaultEntitySettings
} from '../modules/entitySetting/entitySetting-utils';

export const up = async (next) => {
  const context = executionContext('migration');
  const availableEntityTypes = availableSettings.confidence_scale;

  const entitySettings = await listAllEntities(context, SYSTEM_USER, [ENTITY_TYPE_ENTITY_SETTING], { connectionFormat: false });

  for (let index = 0; index < entitySettings.length; index += 1) {
    const entitySetting = entitySettings.at(index);

    if (availableEntityTypes.includes(entitySetting.target_type) && !entitySetting.confidence_scale) {
      const inputs = [{ key: 'confidence_scale', value: [defaultEntitySettings.confidence_scale] }]; // The value must be an array
      await entitySettingEditField(context, SYSTEM_USER, entitySetting.id, inputs);
    }
  }
  next();
};

export const down = async (next) => {
  next();
};
