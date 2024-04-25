import { withFilter } from 'graphql-subscriptions';
import type { Resolvers } from '../../generated/graphql';
import { addSupportPackage, deleteSupportPackage, findAll, findById, requestZipPackage } from './support-domain';
import { pubSubAsyncIterator } from '../../database/redis';
import { BUS_TOPICS } from '../../config/conf';
import { SUPPORT_BUS } from './support-types';

const supportResolvers: Resolvers = {
  Query: {
    supportPackage: (_, { id }, context) => findById(context, context.user, id),
    supportPackages: (_, args, context) => findAll(context, context.user, args),
  },
  Mutation: {
    supportPackageAdd: (_, { input }, context) => {
      return addSupportPackage(context, context.user, input);
    },
    supportPackageForceZip: (_, { input }, context) => {
      return requestZipPackage(context, context.user, input);
    },
    supportPackageDelete: (_, { id }, context) => {
      return deleteSupportPackage(context, context.user, id);
    },
  },
  Subscription: {
    supportPackage: {
      resolve: /* v8 ignore next */ (payload: any) => payload.instance,
      subscribe: /* v8 ignore next */ (_, __, context) => {
        const asyncIterator = pubSubAsyncIterator(BUS_TOPICS[SUPPORT_BUS].EDIT_TOPIC);
        const filtering = withFilter(() => asyncIterator, (payload) => {
          return payload && payload.instance.user_id === context.user.id;
        })();
        return { [Symbol.asyncIterator]() { return filtering; } };
      },
    }
  }
};

export default supportResolvers;
