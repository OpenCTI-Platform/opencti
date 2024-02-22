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
  publicStixCoreObjectsMultiTimeSeries,
  publicStixRelationshipsMultiTimeSeries,
  publicStixRelationshipsNumber,
  publicStixCoreObjectsDistribution,
  publicStixRelationshipsDistribution,
  publicBookmarks,
  publicStixCoreObjects,
  publicStixRelationships,
  publicStixCoreObjectsDistributionBreakdown,
  publicStixRelationshipsDistributionBreakdown,
} from './publicDashboard-domain';
import { getAuthorizedMembers } from '../../utils/authorizedMembers';

const publicDashboardResolvers: Resolvers = {
  Query: {
    publicDashboard: (_, { id }, context) => findById(context, context.user, id),
    publicDashboards: (_, args, context) => findAll(context, context.user, args),
    publicDashboardByUriKey: (_, { uri_key }, context) => getPublicDashboardByUriKey(context, uri_key),
    publicStixCoreObjectsNumber: (_, args, context) => publicStixCoreObjectsNumber(context, args),
    publicStixCoreObjectsMultiTimeSeries: (_, args, context) => publicStixCoreObjectsMultiTimeSeries(context, args),
    publicStixRelationshipsMultiTimeSeries: (_, args, context) => publicStixRelationshipsMultiTimeSeries(context, args),
    publicStixRelationshipsNumber: (_, args, context) => publicStixRelationshipsNumber(context, args),
    publicStixCoreObjectsDistribution: (_, args, context) => publicStixCoreObjectsDistribution(context, args),
    publicStixCoreObjectsDistributionBreakdown: (_, args, context) => publicStixCoreObjectsDistributionBreakdown(context, args),
    publicStixRelationshipsDistribution: (_, args, context) => publicStixRelationshipsDistribution(context, args),
    publicStixRelationshipsDistributionBreakdown: (_, args, context) => publicStixRelationshipsDistributionBreakdown(context, args),
    publicBookmarks: (_, args, context) => publicBookmarks(context, args),
    publicStixCoreObjects: (_, args, context) => publicStixCoreObjects(context, args),
    publicStixRelationships: (_, args, context) => publicStixRelationships(context, args),
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
