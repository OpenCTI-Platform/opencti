import { withFilter } from 'graphql-subscriptions';
import { entitySettingsEditField, findAll, findById, findByType } from './entitySetting-domain';
import type { Resolvers } from '../../generated/graphql';
import { pubSubAsyncIterator } from '../../database/redis';
import { BUS_TOPICS } from '../../config/conf';
import { ENTITY_TYPE_ENTITY_SETTING } from './entitySetting-types';
import { getAvailableSettings } from './entitySetting-utils';

const entitySettingResolvers: Resolvers = {
  Query: {
    entitySetting: (_, { id }, context) => findById(context, context.user, id),
    entitySettings: (_, args, context) => findAll(context, context.user, args),
    entitySettingByType: (_, { targetType }, context) => findByType(context, context.user, targetType),
  },
  EntitySetting: {
    availableSettings: (entitySetting, _, __) => getAvailableSettings(entitySetting.target_type),
  },
  Mutation: {
    entitySettingsFieldPatch: (_, { ids, input }, context) => {
      return entitySettingsEditField(context, context.user, ids, input);
    },
  },
  Subscription: {
    entitySetting: {
      resolve: /* istanbul ignore next */ (payload: any) => {
        return payload.instance;
      },
      subscribe: /* istanbul ignore next */ (_, { id }, __) => {
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
