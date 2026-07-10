import { stixDomainObjectAddRelation, stixDomainObjectDeleteRelation } from '../../../domain/stixDomainObject';
import type { Resolvers } from '../../../generated/graphql';
import { loadThroughDenormalized } from '../../../resolvers/stix';
import { addSecurityCoverageResult, deleteSecurityCoverageResult, findById, findSecurityCoverageResultPaginated } from './securityCoverageResult-domain';
import { INPUT_RESULT_OF } from './securityCoverageResult-types';

const SecurityCoverageResultResolvers: Resolvers = {
  Query: {
    securityCoverageResult: (_, { id }, context) => findById(context, context.user, id),
    securityCoverageResults: (_, args, context) => findSecurityCoverageResultPaginated(context, context.user, args),
  },
  SecurityCoverageResult: {
    resultOf: (scr, _, context) => loadThroughDenormalized(context, context.user, scr, INPUT_RESULT_OF),
  },
  Mutation: {
    securityCoverageResultAdd: (_, { input }, context) => addSecurityCoverageResult(context, context.user, input),
    securityCoverageResultDelete: (_, { id }, context) => deleteSecurityCoverageResult(context, context.user, id),
    securityCoverageResultRelationAdd: (_, { id, input }, context) => stixDomainObjectAddRelation(context, context.user, id, input),
    securityCoverageResultRelationDelete: (_, { id, toId, relationship_type }, context) => stixDomainObjectDeleteRelation(context, context.user, id, toId, relationship_type),
  },
};

export default SecurityCoverageResultResolvers;
