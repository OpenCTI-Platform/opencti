import type { Resolvers } from '../../../generated/graphql';
import { addSecurityCoverageResult, deleteSecurityCoverageResult, findById, findSecurityCoverageResultPaginated } from './securityCoverageResult-domain';

const SecurityCoverageResultResolvers: Resolvers = {
  Query: {
    securityCoverageResult: (_, { id }, context) => findById(context, context.user, id),
    securityCoverageResults: (_, args, context) => findSecurityCoverageResultPaginated(context, context.user, args),
  },
  Mutation: {
    securityCoverageResultAdd: (_, { input }, context) => addSecurityCoverageResult(context, context.user, input),
    securityCoverageResultDelete: (_, { id }, context) => deleteSecurityCoverageResult(context, context.user, id),
  },
};

export default SecurityCoverageResultResolvers;
