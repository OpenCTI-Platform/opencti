import { findThreatActorPaginated, findById as threatActorFindById, threatActorCountriesPaginated, threatActorLocationsPaginated } from '../domain/threatActor';
import { addThreatActorGroup, findThreatActorGroupPaginated, findById as groupFindById } from '../domain/threatActorGroup';
import {
  stixDomainObjectAddRelation,
  stixDomainObjectCleanContext,
  stixDomainObjectDelete,
  stixDomainObjectDeleteRelation,
  stixDomainObjectEditContext,
  stixDomainObjectEditField,
} from '../domain/stixDomainObject';

const threatActorGroupResolvers = {
  Query: {
    threatActor: (_, { id }, context) => threatActorFindById(context, context.user, id),
    threatActors: (_, args, context) => findThreatActorPaginated(context, context.user, args),
    threatActorGroup: (_, { id }, context) => groupFindById(context, context.user, id),
    threatActorsGroup: (_, args, context) => findThreatActorGroupPaginated(context, context.user, args),
  },
  ThreatActor: {
    locations: (threatActor, args, context) => threatActorLocationsPaginated(context, context.user, threatActor.id, args),
    countries: (threatActor, args, context) => threatActorCountriesPaginated(context, context.user, threatActor.id, args),
    __resolveType(obj) {
      if (obj.entity_type) {
        return obj.entity_type.replace(/(?:^|-)(\w)/g, (matches, letter) => letter.toUpperCase());
      }
      return 'Unknown';
    },
  },
  Mutation: {
    threatActorGroupAdd: (_, { input }, context) => addThreatActorGroup(context, context.user, input),
    threatActorGroupEdit: (_, { id }, context) => ({
      delete: () => stixDomainObjectDelete(context, context.user, id),
      fieldPatch: ({ input, commitMessage, references }) => stixDomainObjectEditField(context, context.user, id, input, { commitMessage, references }),
      contextPatch: ({ input }) => stixDomainObjectEditContext(context, context.user, id, input),
      contextClean: () => stixDomainObjectCleanContext(context, context.user, id),
      relationAdd: ({ input }) => stixDomainObjectAddRelation(context, context.user, id, input),
      relationDelete: ({ toId, relationship_type: relationshipType }) => stixDomainObjectDeleteRelation(context, context.user, id, toId, relationshipType),
    }),
  },
};

export default threatActorGroupResolvers;
