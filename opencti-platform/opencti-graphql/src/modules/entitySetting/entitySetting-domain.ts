import type { AuthContext, AuthUser } from '../../types/user';
import { createEntity, loadEntity, updateAttribute } from '../../database/middleware';
import type { BasicStoreEntityEntitySetting } from './entitySetting-types';
import { ENTITY_TYPE_ENTITY_SETTING } from './entitySetting-types';
import { listAllEntities, listEntitiesPaginated, storeLoadById } from '../../database/middleware-loader';
import type { EditInput, QueryEntitySettingsArgs } from '../../generated/graphql';
import { SYSTEM_USER } from '../../utils/access';
import { notify } from '../../database/redis';
import { BUS_TOPICS } from '../../config/conf';
import { defaultEntitySetting, getAvailableSettings, typeAvailableSetting } from './entitySetting-utils';
import { queryDefaultSubTypes } from '../../domain/subType';
import { publishUserAction } from '../../listener/UserActionListener';

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
  return updateAttribute(context, user, entitySettingId, ENTITY_TYPE_ENTITY_SETTING, input)
    .then(async ({ element }) => {
      await publishUserAction({
        user,
        event_type: 'admin',
        status: 'success',
        message: `updates \`${input.map((i) => i.key).join(', ')}\` for entity setting \`${element.target_type}\``,
        context_data: { type: 'setting', operation: 'update', input }
      });
      return notify(BUS_TOPICS[ENTITY_TYPE_ENTITY_SETTING].EDIT_TOPIC, element, user);
    });
};

export const entitySettingsEditField = async (context: AuthContext, user: AuthUser, entitySettingIds: string[], input: EditInput[]) => {
  return Promise.all(entitySettingIds.map((entitySettingId) => entitySettingEditField(context, user, entitySettingId, input)));
};

// -- INITIALIZATION --

export const addEntitySetting = async (context: AuthContext, user: AuthUser, entitySetting: Record<string, typeAvailableSetting>) => {
  const created = await createEntity(context, user, entitySetting, ENTITY_TYPE_ENTITY_SETTING);
  await notify(BUS_TOPICS[ENTITY_TYPE_ENTITY_SETTING].ADDED_TOPIC, created, user);
};

export const initCreateEntitySettings = async (context: AuthContext) => {
  // First check existing
  const subTypes = await queryDefaultSubTypes();
  // Get all current settings
  const entitySettings = await listAllEntities<BasicStoreEntityEntitySetting>(context, SYSTEM_USER, [ENTITY_TYPE_ENTITY_SETTING], { connectionFormat: false });
  const currentEntityTypes = entitySettings.map((e) => e.target_type);
  for (let index = 0; index < subTypes.edges.length; index += 1) {
    const entityType = subTypes.edges[index].node.id;
    // If setting not yet initialize, do it
    if (!currentEntityTypes.includes(entityType)) {
      const availableSettings = getAvailableSettings(entityType);
      const entitySetting: Record<string, typeAvailableSetting> = {
        target_type: entityType
      };
      availableSettings.forEach((key) => {
        if (defaultEntitySetting[key] !== undefined) {
          entitySetting[key] = defaultEntitySetting[key];
        }
      });
      await addEntitySetting(context, SYSTEM_USER, entitySetting);
    }
  }
};
