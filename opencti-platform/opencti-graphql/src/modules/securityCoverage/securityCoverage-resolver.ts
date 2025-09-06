import { addSecurityCoverage, findAll, findById, SecurityCoverageDelete, SecurityCoverageStixBundle, objectAssess } from './securityCoverage-domain';
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
    SecurityCoverage: (_, { id }, context) => findById(context, context.user, id),
    SecurityCoverages: (_, args, context) => findAll(context, context.user, args),
  },
  SecurityCoverage: {
    objectAssess: (SecurityCoverage, _, context) => objectAssess<any>(context, context.user, SecurityCoverage.id),
    toStixBundle: (SecurityCoverage, _, context) => SecurityCoverageStixBundle(context, context.user, SecurityCoverage.id)
  },
  Mutation: {
    SecurityCoverageAdd: (_, { input }, context) => addSecurityCoverage(context, context.user, input),
    SecurityCoverageDelete: (_, { id }, context) => SecurityCoverageDelete(context, context.user, id),
    SecurityCoverageFieldPatch: (_, { id, input, commitMessage, references }, context) => {
      return stixDomainObjectEditField(context, context.user, id, input, { commitMessage, references });
    },
    SecurityCoverageContextPatch: (_, { id, input }, context) => stixDomainObjectEditContext(context, context.user, id, input),
    SecurityCoverageContextClean: (_, { id }, context) => stixDomainObjectCleanContext(context, context.user, id),
    SecurityCoverageRelationAdd: (_, { id, input }, context) => stixDomainObjectAddRelation(context, context.user, id, input),
    SecurityCoverageRelationDelete: (_, { id, toId, relationship_type: relationshipType }, context) => {
      return stixDomainObjectDeleteRelation(context, context.user, id, toId, relationshipType);
    },
  },
};

export default SecurityCoverageResolvers;
