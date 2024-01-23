import { addInfrastructure, findAll, findById } from '../domain/infrastructure';
import {
  stixDomainObjectAddRelation,
  stixDomainObjectCleanContext,
  stixDomainObjectDelete,
  stixDomainObjectDeleteRelation,
  stixDomainObjectEditContext,
  stixDomainObjectEditField,
} from '../domain/stixDomainObject';
import { killChainPhasesPaginated } from '../domain/stixCoreRelationship';

const infrastructureResolvers = {
  Query: {
    infrastructure: (_, { id }, context) => findById(context, context.user, id),
    infrastructures: (_, args, context) => findAll(context, context.user, args),
  },
  Infrastructure: {
    killChainPhases: (infrastructure, args, context) => killChainPhasesPaginated(context, context.user, infrastructure.id, args),
  },
  Mutation: {
    infrastructureEdit: (_, { id }, context) => ({
      delete: () => stixDomainObjectDelete(context, context.user, id),
      fieldPatch: ({ input, commitMessage, references }) => stixDomainObjectEditField(context, context.user, id, input, { commitMessage, references }),
      contextPatch: ({ input }) => stixDomainObjectEditContext(context, context.user, id, input),
      contextClean: () => stixDomainObjectCleanContext(context, context.user, id),
      relationAdd: ({ input }) => stixDomainObjectAddRelation(context, context.user, id, input),
      relationDelete: ({ toId, relationship_type: relationshipType }) => stixDomainObjectDeleteRelation(context, context.user, id, toId, relationshipType),
    }),
    infrastructureAdd: (_, { input }, context) => addInfrastructure(context, context.user, input),
  },
};

export default infrastructureResolvers;
