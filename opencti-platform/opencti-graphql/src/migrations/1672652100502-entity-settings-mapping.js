import { executionContext, SYSTEM_USER } from '../utils/access';
import { getSettings } from '../domain/settings';
import { entitySettingEditField, findByType } from '../modules/entitySetting/entitySetting-domain';
import { queryDefaultSubTypes } from '../domain/subType';
import conf from '../config/conf';
import { elLoadById, elReplace, prepareElementForIndexing } from '../database/engine';
import { ENTITY_TYPE_SETTINGS } from '../schema/internalObject';

export const up = async (next) => {
  const context = executionContext('migration');
  const settings = await getSettings(context);
  const refs = settings.platform_entities_files_ref ?? [];
  const hiddens = settings.platform_hidden_types ?? [];
  const enforceReferences = conf.get('app:enforce_references') ?? [];
  const subTypes = await queryDefaultSubTypes();

  // Setup entity settings
  const migrationEntitySetting = {
    platform_entity_files_ref: (entityType) => refs.includes(entityType),
    platform_hidden_type: (entityType) => hiddens.includes(entityType),
    enforce_reference: (entityType) => enforceReferences.includes(entityType),
  };

  for (let index = 0; index < subTypes.edges.length; index += 1) {
    const entityType = subTypes.edges[index].node.id;

    if (migrationEntitySetting.platform_entity_files_ref(entityType)
      || migrationEntitySetting.platform_hidden_type(entityType)
      || migrationEntitySetting.enforce_reference(entityType)) {
      const entitySetting = await findByType(context, SYSTEM_USER, entityType);
      const inputs = [];

      if (migrationEntitySetting.platform_entity_files_ref(entityType)) {
        inputs.push({ key: 'platform_entity_files_ref', value: [true] });
      }
      if (migrationEntitySetting.platform_hidden_type(entityType)) {
        inputs.push({ key: 'platform_hidden_type', value: [true] });
      }
      if (migrationEntitySetting.enforce_reference(entityType)) {
        inputs.push({ key: 'enforce_reference', value: [true] });
      }

      await entitySettingEditField(context, SYSTEM_USER, entitySetting.id, inputs);
    }
  }

  // Remove setting property from DB

  const settingsFromEl = await elLoadById(context, SYSTEM_USER, settings.id, { type: ENTITY_TYPE_SETTINGS });
  settingsFromEl.platform_entities_files_ref = null;
  settingsFromEl.platform_hidden_types = null;

  const esData = prepareElementForIndexing(settingsFromEl);
  await elReplace(settingsFromEl._index, settingsFromEl.internal_id, { doc: esData });

  next();
};

export const down = async (next) => {
  next();
};
