import type { Resolvers } from '../../generated/graphql';
import type { BasicStoreBase } from '../../types/store';
import type { AuthContext } from '../../types/user';
import {
  addGraphClusterToInvestigation,
  findGraphClusterById,
  findGraphAnalyticsPendingEntities,
  findGraphClusters,
  findSimilarEntities,
  getGraphAnalyticsStatus,
  graphClusterFeatures,
  graphClusterMembers,
  graphClusterPromotedTo,
  graphClusterRepresentatives,
  graphClustersSizeTimeSeries,
  graphClusterTimeline,
  graphSimilarityMatrix,
  listGraphAnalyticsEdges,
  loadGraphMetrics,
  PROMOTION_MAX_MEMBERS,
  promoteGraphCluster,
  recordGraphAnalyticsPivot,
  requestGraphAnalyticsRecompute,
  upsertGraphAnalyticsMetrics,
} from './graphAnalytics-domain';
import { findStixPaths, stixNeighborhoodSummary } from './graphAnalytics-paths';
import type { BasicStoreEntityGraphCluster, GraphClusterKind, GraphClusterSource } from './graphAnalytics-types';

const graphAnalyticsResolvers: Resolvers = {
  Query: {
    stixPaths: (_, args, context) => findStixPaths(context, context.user!, args) as any,
    stixNeighborhoodSummary: (_, { id, includeInferred }, context) => stixNeighborhoodSummary(context, context.user!, id, !!includeInferred),
    similarEntities: (_, args, context) => findSimilarEntities(context, context.user!, args) as any,
    graphSimilarityMatrix: (_, args, context) => graphSimilarityMatrix(context, context.user!, args) as any,
    graphCluster: (_, { id }, context) => findGraphClusterById(context, context.user!, id),
    graphClusters: (_, args, context) => findGraphClusters(context, context.user!, {
      ...args,
      kinds: args.kinds as GraphClusterKind[] | null | undefined,
      sources: args.sources as GraphClusterSource[] | null | undefined,
    }) as any,
    graphClustersSizeTimeSeries: (_, args, context) => graphClustersSizeTimeSeries(context, context.user!, {
      ...args,
      kinds: args.kinds as GraphClusterKind[] | null | undefined,
    }),
    graphAnalyticsStatus: (_, __, context) => getGraphAnalyticsStatus(context, context.user!),
    graphAnalyticsPendingEntities: (_, { first }, context) => findGraphAnalyticsPendingEntities(context, context.user!, first) as any,
    graphAnalyticsEdges: (_, args, context) => listGraphAnalyticsEdges(context, context.user!, args),
  },
  GraphCluster: {
    promotion_max_members: () => PROMOTION_MAX_MEMBERS,
    representatives: (cluster, _, context) => graphClusterRepresentatives(context, context.user!, cluster as BasicStoreEntityGraphCluster) as any,
    features: (cluster, _, context) => graphClusterFeatures(context, context.user!, cluster as BasicStoreEntityGraphCluster) as any,
    promotedTo: (cluster, _, context) => graphClusterPromotedTo(context, context.user!, cluster as BasicStoreEntityGraphCluster) as any,
    members: (cluster, args, context) => graphClusterMembers(context, context.user!, cluster as BasicStoreEntityGraphCluster, args) as any,
    timeline: (cluster, args, context) => graphClusterTimeline(context, context.user!, cluster.id, args),
  },
  Mutation: {
    graphClusterPromote: (_, { id, input }, context) => promoteGraphCluster(context, context.user!, id, input) as any,
    graphClusterAddToInvestigation: (_, { id, investigationId }, context) => addGraphClusterToInvestigation(context, context.user!, id, investigationId) as any,
    graphAnalyticsUpsertMetrics: (_, { input }, context) => upsertGraphAnalyticsMetrics(context, context.user!, input),
    graphAnalyticsRequestRecompute: (_, { ids }, context) => requestGraphAnalyticsRecompute(context, context.user!, ids),
    graphAnalyticsRecordPivot: () => recordGraphAnalyticsPivot(),
  },
};

// Interface field resolver, inherited by every Stix Core Object type (the generated interface type would also require __resolveType)
const stixCoreObjectResolvers = {
  x_opencti_graph_metrics: (stixCoreObject: BasicStoreBase, _: unknown, context: AuthContext) => loadGraphMetrics(context, context.user!, stixCoreObject),
};

const resolvers: Record<string, unknown> = { ...graphAnalyticsResolvers, StixCoreObject: stixCoreObjectResolvers };

export default resolvers;
