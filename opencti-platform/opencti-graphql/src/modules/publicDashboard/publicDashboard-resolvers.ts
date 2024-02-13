import type { Resolvers } from '../../generated/graphql';
import {
  addPublicDashboard,
  findById,
  findAll,
  publicDashboardDelete,
  publicDashboardEditField,
  getPublicDashboardByUriKey,
  getAllowedMarkings,
  publicStixCoreObjectsNumber,
  publicStixCoreObjectsMultiTimeSeries
} from './publicDashboard-domain';
import { getAuthorizedMembers } from '../../utils/authorizedMembers';

const publicDashboardResolvers: Resolvers = {
  Query: {
    publicDashboard: (_, { id }, context) => findById(context, context.user, id),
    publicDashboards: (_, args, context) => findAll(context, context.user, args),
    publicDashboardByUriKey: (_, { uri_key }, context) => getPublicDashboardByUriKey(context, uri_key),
    publicStixCoreObjectsNumber: (_, args, context) => publicStixCoreObjectsNumber(context, args),
    publicStixCoreObjectsMultiTimeSeries: (_, args, context) => publicStixCoreObjectsMultiTimeSeries(context, args),
  },
  PublicDashboard: {
    authorized_members: (publicDashboard, _, context) => getAuthorizedMembers(context, context.user, publicDashboard),
    allowed_markings: (publicDashboard, _, context) => getAllowedMarkings(context, context.user, publicDashboard),
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
