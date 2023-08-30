import {
  batchCountries,
  batchLocations,
  findAll as genericFindAll,
  findById as genericFindById
} from '../domain/threatActor';
import { addThreatActorGroup, findAll as groupFindAll, findById as groupFindById } from '../domain/threatActorGroup';
import {
  stixDomainObjectAddRelation,
  stixDomainObjectCleanContext,
  stixDomainObjectDelete,
  stixDomainObjectDeleteRelation,
  stixDomainObjectEditContext,
  stixDomainObjectEditField,
} from '../domain/stixDomainObject';
import { batchLoader } from '../database/middleware';

const locationsLoader = batchLoader(batchLocations);
const countriesLoader = batchLoader(batchCountries);

const threatActorGroupResolvers = {
  Query: {
    threatActor: (_, { id }, context) => genericFindById(context, context.user, id),
    threatActors: (_, args, context) => genericFindAll(context, context.user, args),
    threatActorGroup: (_, { id }, context) => groupFindById(context, context.user, id),
    threatActorsGroup: (_, args, context) => groupFindAll(context, context.user, args),
  },
  ThreatActor: {
    locations: (threatActor, _, context) => locationsLoader.load(threatActor.id, context, context.user),
    countries: (threatActor, _, context) => countriesLoader.load(threatActor.id, context, context.user),
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
