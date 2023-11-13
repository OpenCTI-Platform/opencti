import { withFilter } from 'graphql-subscriptions';
import type { Resolvers } from '../../generated/graphql';
import {
  findById,
  findByManagerId,
  getManagerSettings,
  managerConfigurationEditField
} from './managerConfiguration-domain';
import { pubSubAsyncIterator } from '../../database/redis';
import { BUS_TOPICS } from '../../config/conf';
import { ENTITY_TYPE_MANAGER_CONFIGURATION } from './managerConfiguration-types';

const managerConfigurationResolvers: Resolvers = {
  Query: {
    managerConfiguration: (_, { id }, context) => findById(context, context.user, id),
    managerConfigurationByManagerId: (_, { managerId }, context) => findByManagerId(context, context.user, managerId),
  },
  ManagerConfiguration: {
    manager_settings: (current) => getManagerSettings(current.manager_id),
  },
  Mutation: {
    managerConfigurationFieldPatch: (_, { id, input }, context) => {
      return managerConfigurationEditField(context, context.user, id, input);
    },
  },
  Subscription: {
    managerConfiguration: {
      resolve: /* istanbul ignore next */ (payload: any) => {
        return payload.instance;
      },
      subscribe: /* istanbul ignore next */ (_, { id }, __) => {
        const asyncIterator = pubSubAsyncIterator(BUS_TOPICS[ENTITY_TYPE_MANAGER_CONFIGURATION].EDIT_TOPIC);
        const filtering = withFilter(() => asyncIterator, (payload) => {
          return payload.instance.id === id;
        })();
        return { [Symbol.asyncIterator]() { return filtering; } };
      },
    },
  }
};

export default managerConfigurationResolvers;
