import { addThreatActor, findAll, findById, batchLocations, batchCountries } from '../domain/threatActor';
import {
  stixDomainObjectAddRelation,
  stixDomainObjectCleanContext,
  stixDomainObjectDelete,
  stixDomainObjectDeleteRelation,
  stixDomainObjectEditContext,
  stixDomainObjectEditField,
} from '../domain/stixDomainObject';
import {
  RELATION_CREATED_BY,
  RELATION_OBJECT_ASSIGNEE,
  RELATION_OBJECT_LABEL,
  RELATION_OBJECT_MARKING
} from '../schema/stixRefRelationship';
import { buildRefRelationKey } from '../schema/general';
import { batchLoader } from '../database/middleware';

const locationsLoader = batchLoader(batchLocations);
const countriesLoader = batchLoader(batchCountries);

const threatActorResolvers = {
  Query: {
    threatActor: (_, { id }, context) => findById(context, context.user, id),
    threatActors: (_, args, context) => findAll(context, context.user, args),
  },
  ThreatActor: {
    locations: (threatActor, _, context) => locationsLoader.load(threatActor.id, context, context.user),
    countries: (threatActor, _, context) => countriesLoader.load(threatActor.id, context, context.user),
  },
  ThreatActorsFilter: {
    createdBy: buildRefRelationKey(RELATION_CREATED_BY),
    assigneeTo: buildRefRelationKey(RELATION_OBJECT_ASSIGNEE),
    markedBy: buildRefRelationKey(RELATION_OBJECT_MARKING),
    labelledBy: buildRefRelationKey(RELATION_OBJECT_LABEL),
    creator: 'creator_id',
  },
  Mutation: {
    threatActorEdit: (_, { id }, context) => ({
      delete: () => stixDomainObjectDelete(context, context.user, id),
      fieldPatch: ({ input, commitMessage, references }) => stixDomainObjectEditField(context, context.user, id, input, { commitMessage, references }),
      contextPatch: ({ input }) => stixDomainObjectEditContext(context, context.user, id, input),
      contextClean: () => stixDomainObjectCleanContext(context, context.user, id),
      relationAdd: ({ input }) => stixDomainObjectAddRelation(context, context.user, id, input),
      relationDelete: ({ toId, relationship_type: relationshipType }) => stixDomainObjectDeleteRelation(context, context.user, id, toId, relationshipType),
    }),
    threatActorAdd: (_, { input }, context) => addThreatActor(context, context.user, input),
  },
};

export default threatActorResolvers;
