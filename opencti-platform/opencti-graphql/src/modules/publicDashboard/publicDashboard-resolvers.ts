import type { Resolvers } from '../../generated/graphql';
import {
  addPublicDashboard,
  findPublicDashboardPaginated,
  findById,
  getAllowedMarkings,
  getPublicDashboardByUriKey,
  publicBookmarks,
  publicDashboardDelete,
  publicDashboardEditField,
  publicStixCoreObjectsPaginated,
  publicStixCoreObjectsDistribution,
  publicStixCoreObjectsMultiTimeSeries,
  publicStixCoreObjectsNumber,
  publicStixRelationships,
  publicStixRelationshipsDistribution,
  publicStixRelationshipsMultiTimeSeries,
  publicStixRelationshipsNumber,
} from './publicDashboard-domain';
import { findById as findWorkspaceById } from '../workspace/workspace-domain';

const publicDashboardResolvers: Resolvers = {
  Query: {
    publicDashboard: (_, { id }, context) => findById(context, context.user, id),
    publicDashboards: (_, args, context) => findPublicDashboardPaginated(context, context.user, args),
    publicDashboardByUriKey: (_, { uri_key }, context) => getPublicDashboardByUriKey(context, uri_key),
    publicStixCoreObjectsNumber: (_, args, context) => publicStixCoreObjectsNumber(context, args),
    publicStixCoreObjectsMultiTimeSeries: (_, args, context) => publicStixCoreObjectsMultiTimeSeries(context, args),
    publicStixRelationshipsMultiTimeSeries: (_, args, context) => publicStixRelationshipsMultiTimeSeries(context, args),
    publicStixRelationshipsNumber: (_, args, context) => publicStixRelationshipsNumber(context, args),
    publicStixCoreObjectsDistribution: (_, args, context) => publicStixCoreObjectsDistribution(context, args),
    publicStixRelationshipsDistribution: (_, args, context) => publicStixRelationshipsDistribution(context, args),
    publicBookmarks: (_, args, context) => publicBookmarks(context, args),
    publicStixCoreObjects: (_, args, context) => publicStixCoreObjectsPaginated(context, args),
    publicStixRelationships: (_, args, context) => publicStixRelationships(context, args),
  },
  PublicDashboard: {
    allowed_markings: (publicDashboard, _, context) => getAllowedMarkings(context, context.user, publicDashboard),
    owner: (publicDashboard, _, context) => context.batch.creatorBatchLoader.load(publicDashboard.user_id),
    dashboard: (publicDashboard, _, context) => findWorkspaceById(context, context.user, publicDashboard.dashboard_id)
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
