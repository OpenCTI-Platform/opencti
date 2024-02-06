import { withFilter } from 'graphql-subscriptions';
import { entitySettingsEditField, findAll, findById, findByType, queryDefaultValuesAttributesForSetting, queryEntitySettingSchemaAttributes, queryMandatoryAttributesForSetting, queryScaleAttributesForSetting } from './entitySetting-domain';
import { pubSubAsyncIterator } from '../../database/redis';
import { BUS_TOPICS } from '../../config/conf';
import { ENTITY_TYPE_ENTITY_SETTING } from './entitySetting-types';
import { getAvailableSettings } from './entitySetting-utils';
const entitySettingResolvers = {
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
    },
    Mutation: {
        entitySettingsFieldPatch: (_, { ids, input }, context) => {
            return entitySettingsEditField(context, context.user, ids, input);
        },
    },
    Subscription: {
        entitySetting: {
            resolve: /* v8 ignore next */ (payload) => {
                return payload.instance;
            },
            subscribe: /* v8 ignore next */ (_, { id }, __) => {
                const asyncIterator = pubSubAsyncIterator(BUS_TOPICS[ENTITY_TYPE_ENTITY_SETTING].EDIT_TOPIC);
                const filtering = withFilter(() => asyncIterator, (payload) => {
                    return payload.instance.id === id;
                })();
                return { [Symbol.asyncIterator]() { return filtering; } };
            },
        },
    }
};
export default entitySettingResolvers;
