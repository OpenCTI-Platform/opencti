import type { AuthContext, AuthUser } from '../../types/user';
import { createEntity, loadEntity, updateAttribute } from '../../database/middleware';
import { ENTITY_TYPE_ENTITY_SETTING } from '../../schema/internalObject';
import type { BasicStoreEntityEntitySetting } from './entitySetting-types';
import { listAllEntities, listEntitiesPaginated, storeLoadById } from '../../database/middleware-loader';
import type { EditInput, QueryEntitySettingsArgs } from '../../generated/graphql';
import { SYSTEM_USER } from '../../utils/access';
import { notify } from '../../database/redis';
import { BUS_TOPICS } from '../../config/conf';
import { defaultEntitySetting, getAvailableSettings } from './entitySetting-utils';
import { getEntitiesMapFromCache } from '../../database/cache';
import { UnsupportedError } from '../../config/errors';
import { queryDefaultSubTypes } from '../../domain/subType';

// -- VALIDATION --

const upsertValidation = async (context: AuthContext, user: AuthUser, entitySettingId: string, input: EditInput[]) => {
  const entitySettings = await getEntitiesMapFromCache<BasicStoreEntityEntitySetting>(context, user, ENTITY_TYPE_ENTITY_SETTING);
  const entitySetting = entitySettings.get(entitySettingId);
  if (!entitySetting) {
    throw UnsupportedError('This setting does not exist', { id: entitySettingId });
  }

  const settings = getAvailableSettings(entitySetting.target_type);
  input.forEach((i) => {
    if (!settings.includes(i.key)) {
      throw UnsupportedError('This setting is not available for this entity', {
        setting: i.key,
        entity: entitySetting.target_type
      });
    }
  });
};

// -- LOADING --

export const findById = (context: AuthContext, user: AuthUser, entitySettingId: string): BasicStoreEntityEntitySetting => {
  return storeLoadById(context, user, entitySettingId, ENTITY_TYPE_ENTITY_SETTING) as unknown as BasicStoreEntityEntitySetting;
};

export const findByType = (context: AuthContext, user: AuthUser, targetType: string): BasicStoreEntityEntitySetting => {
  return loadEntity(context, user, [ENTITY_TYPE_ENTITY_SETTING], {
    filters: [{ key: 'target_type', values: [targetType] }]
  }) as unknown as BasicStoreEntityEntitySetting;
};

export const findAll = (context: AuthContext, user: AuthUser, opts: QueryEntitySettingsArgs) => {
  return listEntitiesPaginated<BasicStoreEntityEntitySetting>(context, user, [ENTITY_TYPE_ENTITY_SETTING], opts);
};

export const entitySettingEditField = async (context: AuthContext, user: AuthUser, entitySettingId: string, input: EditInput[]) => {
  return upsertValidation(context, user, entitySettingId, input)
    .then(() => updateAttribute(context, user, entitySettingId, ENTITY_TYPE_ENTITY_SETTING, input))
    .then(({ element }) => notify(BUS_TOPICS[ENTITY_TYPE_ENTITY_SETTING].EDIT_TOPIC, element, user));
};

export const entitySettingsEditField = async (context: AuthContext, user: AuthUser, entitySettingIds: string[], input: EditInput[]) => {
  return Promise.all(entitySettingIds.map((entitySettingId) => entitySettingEditField(context, user, entitySettingId, input)));
};

// -- INITIALIZATION --

export const addEntitySetting = async (context: AuthContext, user: AuthUser, entitySetting: Record<string, string | boolean>) => {
  const created = await createEntity(context, user, entitySetting, ENTITY_TYPE_ENTITY_SETTING);
  return notify(BUS_TOPICS[ENTITY_TYPE_ENTITY_SETTING].ADDED_TOPIC, created, user) as BasicStoreEntityEntitySetting;
};

export const initCreateEntitySettings = async (context: AuthContext) => {
  // First check existing
  const subTypes = await queryDefaultSubTypes();
  // Get all current settings
  const entitySettings = await listAllEntities(context, SYSTEM_USER, [ENTITY_TYPE_ENTITY_SETTING], { connectionFormat: false });
  const currentEntityTypes = entitySettings.map((e) => e.entity_type);
  for (let index = 0; index < subTypes.edges.length; index += 1) {
    const entityType = subTypes.edges[index].node.id;
    // If setting not yet initialize, do it
    if (!currentEntityTypes.includes(entityType)) {
      const availableSettings = getAvailableSettings(entityType);
      const entitySetting: Record<string, string | boolean> = {
        target_type: entityType
      };
      availableSettings.forEach((key) => {
        entitySetting[key] = defaultEntitySetting[key]();
      });
      await addEntitySetting(context, SYSTEM_USER, entitySetting);
    }
  }
};
