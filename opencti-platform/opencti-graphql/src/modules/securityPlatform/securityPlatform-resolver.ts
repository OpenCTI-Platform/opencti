import { addSecurityPlatform, findSecurityPlatformPaginated, findById, securityPlatformDelete } from './securityPlatform-domain';
import {
  stixDomainObjectAddRelation,
  stixDomainObjectCleanContext,
  stixDomainObjectDeleteRelation,
  stixDomainObjectEditContext,
  stixDomainObjectEditField
} from '../../domain/stixDomainObject';
import type { Resolvers } from '../../generated/graphql';

const securityPlatformResolvers: Resolvers = {
  Query: {
    securityPlatform: (_, { id }, context) => findById(context, context.user, id),
    securityPlatforms: (_, args, context) => findSecurityPlatformPaginated(context, context.user, args),
  },
  Mutation: {
    securityPlatformAdd: (_, { input }, context) => addSecurityPlatform(context, context.user, input),
    securityPlatformDelete: (_, { id }, context) => securityPlatformDelete(context, context.user, id),
    securityPlatformFieldPatch: (_, { id, input, commitMessage, references }, context) => {
      return stixDomainObjectEditField(context, context.user, id, input, { commitMessage, references });
    },
    securityPlatformContextPatch: (_, { id, input }, context) => stixDomainObjectEditContext(context, context.user, id, input),
    securityPlatformContextClean: (_, { id }, context) => stixDomainObjectCleanContext(context, context.user, id),
    securityPlatformRelationAdd: (_, { id, input }, context) => stixDomainObjectAddRelation(context, context.user, id, input),
    securityPlatformRelationDelete: (_, { id, toId, relationship_type: relationshipType }, context) => {
      return stixDomainObjectDeleteRelation(context, context.user, id, toId, relationshipType);
    },
  },
};

export default securityPlatformResolvers;
