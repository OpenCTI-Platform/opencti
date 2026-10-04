import type { Resolvers } from '../../generated/graphql';
import {
  disseminationAssuranceMetrics,
  removeIndicatorDeployment,
  reportIndicatorDeployment,
  reportIndicatorDeployments,
  reportIndicatorHits,
  retryIndicatorDeployment,
} from './indicatorDeployment-domain';

// Deployment attributes are stored flat on the relationship and resolved by the default field resolvers.
const indicatorDeploymentResolvers: Resolvers = {
  Query: {
    disseminationAssuranceMetrics: (_, args, context) => disseminationAssuranceMetrics(context, context.user!, args) as never,
  },
  Mutation: {
    indicatorReportDeployment: (_, args, context) => reportIndicatorDeployment(context, context.user!, args) as never,
    indicatorReportDeployments: (_, { platformId, reports }, context) => reportIndicatorDeployments(context, context.user!, platformId, reports),
    indicatorReportHits: (_, args, context) => reportIndicatorHits(context, context.user!, args) as never,
    indicatorDeploymentRetry: (_, { id }, context) => retryIndicatorDeployment(context, context.user!, id) as never,
    indicatorDeploymentRemove: (_, { id }, context) => removeIndicatorDeployment(context, context.user!, id) as never,
  },
};

export default indicatorDeploymentResolvers;
