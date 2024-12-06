import {
  entitySettingsEditField,
  findAll,
  findById,
  findByType,
  getOverviewLayoutCustomization,
  getTemplatesForSetting,
  queryDefaultValuesAttributesForSetting,
  queryEntitySettingSchemaAttributes,
  queryMandatoryAttributesForSetting,
  queryScaleAttributesForSetting
} from './entitySetting-domain';
import type { Resolvers } from '../../generated/graphql';
import { BUS_TOPICS } from '../../config/conf';
import { ENTITY_TYPE_ENTITY_SETTING } from './entitySetting-types';
import { getAvailableSettings } from './entitySetting-utils';
import { subscribeToInstanceEvents } from '../../graphql/subscriptionWrapper';

const entitySettingResolvers: Resolvers = {
  Query: {
    entitySetting: (_, { id }, context) => findById(context, context.user, id),
    entitySettings: (_, args, context) => findAll(context, context.user, args),
    entitySettingByType: (_, { targetType }, context) => findByType(context, context.user, targetType),
  },
  EntitySetting: {
    attributesDefinitions: (entitySetting, _, context) => queryEntitySettingSchemaAttributes(context, context.user, entitySetting),
    mandatoryAttributes: (entitySetting, _, context) => queryMandatoryAttributesForSetting(context, context.user, entitySetting),
    scaleAttributes: (entitySetting, _, context) => queryScaleAttributesForSetting(context, context.user, entitySetting),
    defaultValuesAttributes: (entitySetting, _, context) => queryDefaultValuesAttributesForSetting(context, context.user, entitySetting),
    availableSettings: (entitySetting, _, __) => getAvailableSettings(entitySetting.target_type),
    overview_layout_customization: (entitySetting, _, __) => getOverviewLayoutCustomization(entitySetting),
    fintelTemplates: (entitySetting, _, context) => getTemplatesForSetting(context, context.user, entitySetting.target_type),
  },
  Mutation: {
    entitySettingsFieldPatch: (_, { ids, input }, context) => {
      return entitySettingsEditField(context, context.user, ids, input);
    },
  },
  Subscription: {
    entitySetting: {
      resolve: /* v8 ignore next */ (payload: any) => {
        return payload.instance;
      },
      subscribe: /* v8 ignore next */ (_, { id }, context) => {
        const bus = BUS_TOPICS[ENTITY_TYPE_ENTITY_SETTING];
        return subscribeToInstanceEvents(_, context, id, [bus.EDIT_TOPIC], { type: ENTITY_TYPE_ENTITY_SETTING, notifySelf: true });
      },
    },
  }
};

export default entitySettingResolvers;
