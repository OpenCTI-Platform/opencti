import {
  addSecurityCoverage,
  pageSecurityCoverageConnections,
  findSecurityCoverageById,
  securityCoverageDelete,
  securityCoverageStixBundle,
  objectCovered
} from './securityCoverage-domain';
import {
  stixDomainObjectAddRelation,
  stixDomainObjectCleanContext,
  stixDomainObjectDeleteRelation,
  stixDomainObjectEditContext,
  stixDomainObjectEditField
} from '../../domain/stixDomainObject';
import type { Resolvers } from '../../generated/graphql';

const SecurityCoverageResolvers: Resolvers = {
  Query: {
    securityCoverage: (_, { id }, context) => findSecurityCoverageById(context, context.user, id),
    securityCoverages: (_, args, context) => pageSecurityCoverageConnections(context, context.user, args),
  },
  SecurityCoverage: {
    objectCovered: (SecurityCoverage, _, context) => objectCovered<any>(context, context.user, SecurityCoverage.id),
    toStixBundle: (SecurityCoverage, _, context) => securityCoverageStixBundle(context, context.user, SecurityCoverage.id)
  },
  Mutation: {
    securityCoverageAdd: (_, { input }, context) => addSecurityCoverage(context, context.user, input),
    securityCoverageDelete: (_, { id }, context) => securityCoverageDelete(context, context.user, id),
    securityCoverageFieldPatch: (_, { id, input, commitMessage, references }, context) => {
      return stixDomainObjectEditField(context, context.user, id, input, { commitMessage, references });
    },
    securityCoverageContextPatch: (_, { id, input }, context) => stixDomainObjectEditContext(context, context.user, id, input),
    securityCoverageContextClean: (_, { id }, context) => stixDomainObjectCleanContext(context, context.user, id),
    securityCoverageRelationAdd: (_, { id, input }, context) => stixDomainObjectAddRelation(context, context.user, id, input),
    securityCoverageRelationDelete: (_, { id, toId, relationship_type: relationshipType }, context) => {
      return stixDomainObjectDeleteRelation(context, context.user, id, toId, relationshipType);
    },
  },
};

export default SecurityCoverageResolvers;
