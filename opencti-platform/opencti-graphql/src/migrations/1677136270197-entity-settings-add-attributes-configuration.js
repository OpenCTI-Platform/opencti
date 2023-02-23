import { executionContext, SYSTEM_USER } from '../utils/access';
import { entitySettingsEditField } from '../modules/entitySetting/entitySetting-domain';
import { listAllEntities } from '../database/middleware-loader';
import { ENTITY_TYPE_ENTITY_SETTING } from '../modules/entitySetting/entitySetting-types';
import { defaultEntitySetting, getAvailableSettings } from '../modules/entitySetting/entitySetting-utils';

export const up = async (next) => {
  const context = executionContext('migration');
  const entitySettings = await listAllEntities(context, SYSTEM_USER, [ENTITY_TYPE_ENTITY_SETTING], { connectionFormat: false });
  const entitySettingIds = [];
  for (let index = 0; index < entitySettings.length; index += 1) {
    const availableSettings = getAvailableSettings(entitySettings[index].target_type);
    if (availableSettings.includes('attributes_configuration')) {
      entitySettingIds.push(entitySettings[index].id);
    }
  }
  await entitySettingsEditField(context, SYSTEM_USER, entitySettingIds, { key: 'attributes_configuration', value: [defaultEntitySetting.attributes_configuration] });

  next();
};

export const down = async (next) => {
  next();
};
