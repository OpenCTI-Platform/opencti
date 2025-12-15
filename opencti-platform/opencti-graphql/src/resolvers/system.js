import { addSystem, belongsToOrganizationsPaginated, findSystemPaginated, findById } from '../domain/system';
import {
  stixDomainObjectAddRelation,
  stixDomainObjectCleanContext,
  stixDomainObjectDeleteRelation,
  stixDomainObjectDelete,
  stixDomainObjectEditContext,
  stixDomainObjectEditField,
} from '../domain/stixDomainObject';
import { ENTITY_TYPE_IDENTITY_SYSTEM } from '../schema/stixDomainObject';

const systemResolvers = {
  Query: {
    system: (_, { id }, context) => findById(context, context.user, id),
    systems: (_, args, context) => findSystemPaginated(context, context.user, args),
  },
  System: {
    organizations: (system, args, context) => belongsToOrganizationsPaginated(context, context.user, system.id, args),
  },
  Mutation: {
    systemEdit: (_, { id }, context) => ({
      delete: () => stixDomainObjectDelete(context, context.user, id, ENTITY_TYPE_IDENTITY_SYSTEM),
      fieldPatch: ({ input, commitMessage, references }) => stixDomainObjectEditField(context, context.user, id, input, { commitMessage, references }),
      contextPatch: ({ input }) => stixDomainObjectEditContext(context, context.user, id, input),
      contextClean: () => stixDomainObjectCleanContext(context, context.user, id),
      relationAdd: ({ input }) => stixDomainObjectAddRelation(context, context.user, id, input),
      relationDelete: ({ toId, relationship_type: relationshipType }) => stixDomainObjectDeleteRelation(context, context.user, id, toId, relationshipType),
    }),
    systemAdd: (_, { input }, context) => addSystem(context, context.user, input),
  },
};

export default systemResolvers;
