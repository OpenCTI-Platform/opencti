import { addInfrastructure, findInfrastructurePaginated, findById } from '../domain/infrastructure';
import {
  stixDomainObjectAddRelation,
  stixDomainObjectCleanContext,
  stixDomainObjectDeleteRelation,
  stixDomainObjectDelete,
  stixDomainObjectEditContext,
  stixDomainObjectEditField,
} from '../domain/stixDomainObject';
import { ENTITY_TYPE_INFRASTRUCTURE } from '../schema/stixDomainObject';
import { loadThroughDenormalized } from './stix';
import { INPUT_KILLCHAIN } from '../schema/general';

const infrastructureResolvers = {
  Query: {
    infrastructure: (_, { id }, context) => findById(context, context.user, id),
    infrastructures: (_, args, context) => findInfrastructurePaginated(context, context.user, args),
  },
  Infrastructure: {
    killChainPhases: (infrastructure, _, context) => loadThroughDenormalized(context, context.user, infrastructure, INPUT_KILLCHAIN, { sortBy: 'phase_name' }),
  },
  Mutation: {
    infrastructureEdit: (_, { id }, context) => ({
      delete: () => stixDomainObjectDelete(context, context.user, id, ENTITY_TYPE_INFRASTRUCTURE),
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
