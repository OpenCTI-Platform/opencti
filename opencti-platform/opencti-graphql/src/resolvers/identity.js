import { addIdentity, findIdentityPaginated, findById } from '../domain/identity';
import {
  stixDomainObjectAddRelation,
  stixDomainObjectCleanContext,
  stixDomainObjectDeleteRelation,
  stixDomainObjectDelete,
  stixDomainObjectEditContext,
  stixDomainObjectEditField,
} from '../domain/stixDomainObject';
import { ENTITY_TYPE_IDENTITY } from '../schema/general';

const identityResolvers = {
  Query: {
    identity: (_, { id }, context) => findById(context, context.user, id),
    identities: (_, args, context) => findIdentityPaginated(context, context.user, args),
  },
  Identity: {
    __resolveType(obj) {
      if (obj.entity_type) {
        return obj.entity_type.replace(/(?:^|-)(\w)/g, (matches, letter) => letter.toUpperCase());
      }
      return 'Unknown';
    },
  },
  Mutation: {
    identityEdit: (_, { id }, context) => ({
      delete: () => stixDomainObjectDelete(context, context.user, id, ENTITY_TYPE_IDENTITY),
      fieldPatch: ({ input, commitMessage, references }) => stixDomainObjectEditField(context, context.user, id, input, { commitMessage, references }),
      contextPatch: ({ input }) => stixDomainObjectEditContext(context, context.user, id, input),
      contextClean: () => stixDomainObjectCleanContext(context, context.user, id),
      relationAdd: ({ input }) => stixDomainObjectAddRelation(context, context.user, id, input),
      relationDelete: ({ toId, relationship_type: relationshipType }) => stixDomainObjectDeleteRelation(context, context.user, id, toId, relationshipType),
    }),
    identityAdd: (_, { input }, context) => addIdentity(context, context.user, input),
  },
};

export default identityResolvers;
