import { addSecurityCoverage, findAll, findById, securityCoverageDelete, securityCoverageStixBundle, objectAssess } from './securityCoverage-domain';
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
    securityCoverage: (_, { id }, context) => findById(context, context.user, id),
    securityCoverages: (_, args, context) => findAll(context, context.user, args),
  },
  SecurityCoverage: {
    objectAssess: (SecurityCoverage, _, context) => objectAssess<any>(context, context.user, SecurityCoverage.id),
    toStixBundle: (SecurityCoverage, _, context) => securityCoverageStixBundle(context, context.user, SecurityCoverage.id)
  },
  StixCoverageAssessObject: {
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore
    __resolveType(obj) {
      if (obj.entity_type) {
        return obj.entity_type.replace(/(?:^|-)(\w)/g, (matches, letter) => letter.toUpperCase());
      }
      return 'Unknown';
    },
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
