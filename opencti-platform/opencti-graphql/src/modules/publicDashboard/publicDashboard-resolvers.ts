import type { Resolvers } from '../../generated/graphql';
import { addPublicDashboard, findById, findAll, publicDashboardDelete, publicDashboardEditField, getPublicDashboard } from './publicDashboard-domain';

const publicDashboardResolvers: Resolvers = {
  Query: {
    publicDashboard: (_, { id }, context) => findById(context, context.user, id),
    publicDashboards: (_, args, context) => findAll(context, context.user, args),
    publicDashboardPublic: (_, { uri_key }, context) => getPublicDashboard(context, uri_key),
  },
  Mutation: {
    publicDashboardAdd: (_, { input }, context) => {
      return addPublicDashboard(context, context.user, input);
    },
    publicDashboardDelete: (_, { id }, context) => {
      return publicDashboardDelete(context, context.user, id);
    },
    publicDashboardFieldPatch: (_, { id, input }, context) => {
      return publicDashboardEditField(context, context.user, id, input);
    },
  },
};

export default publicDashboardResolvers;
