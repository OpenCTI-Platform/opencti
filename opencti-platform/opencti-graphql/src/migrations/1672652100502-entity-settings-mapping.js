import { executionContext, SYSTEM_USER } from '../utils/access';
import { getSettings, settingsEditField } from '../domain/settings';
import { addEntitySetting } from '../modules/entitySetting/entitySetting-domain';
import { getAvailableSettings } from '../modules/entitySetting/entitySetting-utils';
import { UPDATE_OPERATION_REMOVE } from '../database/utils';
import { queryDefaultSubTypes } from '../domain/subType';
import conf from '../config/conf';

export const up = async (next) => {
  const context = executionContext('migration');
  const settings = await getSettings(context);
  const refs = settings.platform_entities_files_ref ?? [];
  const hiddens = settings.platform_hidden_types ?? [];
  const subTypes = await queryDefaultSubTypes(); // based on entitySetting-domain.initCreateEntitySettings
  for (let index = 0; index < subTypes.edges.length; index += 1) {
    // Setup entity settings
    const migrationEntitySetting = {
      platform_entity_files_ref: () => refs.includes(subTypes.edges[index].node.id),
      platform_hidden_type: () => hiddens.includes(subTypes.edges[index].node.id),
      enforce_reference: () => conf.get('app:enforce_references'),
    };

    const entityType = subTypes.edges[index].node.id;
    const availableSettings = getAvailableSettings(entityType);
    const entitySetting = {
      target_type: entityType
    };
    availableSettings.forEach((key) => {
      entitySetting[key] = migrationEntitySetting[key]();
    });
    await addEntitySetting(context, SYSTEM_USER, entitySetting);
  }

  // Remove setting property from DB
  const updates = [
    { key: 'platform_entities_files_ref', value: null, operation: UPDATE_OPERATION_REMOVE },
    { key: 'platform_hidden_types', value: null, operation: UPDATE_OPERATION_REMOVE }
  ];
  await settingsEditField(context, SYSTEM_USER, settings.id, updates);

  next();
};

export const down = async (next) => {
  next();
};
