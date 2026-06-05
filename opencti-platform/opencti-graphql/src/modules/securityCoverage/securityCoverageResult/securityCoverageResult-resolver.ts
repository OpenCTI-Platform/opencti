import type { Resolvers } from '../../../generated/graphql';
import {
  addSecurityCoverageResult,
  deleteSecurityCoverageResult,
  findSecurityCoverageResultById,
  listSecurityCoverageResultsByResultOf,
  pageSecurityCoverageResults,
} from './securityCoverageResult-domain';

const SecurityCoverageResultResolvers: Resolvers = {
  Query: {
    securityCoverageResult: (_, { id }, context) => findSecurityCoverageResultById(context, context.user, id),
    securityCoverageResults: (_, args, context) => pageSecurityCoverageResults(context, context.user, args),
    listSecurityCoverageResultsByResultOf: (_, { id }, context) => listSecurityCoverageResultsByResultOf(context, context.user, id),
  },
  Mutation: {
    securityCoverageResultAdd: (_, { input }, context) => addSecurityCoverageResult(context, context.user, input),
    securityCoverageResultDelete: (_, { id }, context) => deleteSecurityCoverageResult(context, context.user, id),
  },
};

export default SecurityCoverageResultResolvers;
