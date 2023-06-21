import { addThreatActorGroup, findAll, findById, batchLocations, batchCountries } from '../domain/threatActorGroup';
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

const threatActorGroupResolvers = {
  Query: {
    threatActorGroup: (_, { id }, context) => findById(context, context.user, id),
    threatActorsGroup: (_, args, context) => findAll(context, context.user, args),
  },
  threatActorGroup: {
    locations: (threatActorGroup, _, context) => locationsLoader.load(threatActorGroup.id, context, context.user),
    countries: (threatActorGroup, _, context) => countriesLoader.load(threatActorGroup.id, context, context.user),
  },
  threatActorsGroupFilter: {
    createdBy: buildRefRelationKey(RELATION_CREATED_BY),
    assigneeTo: buildRefRelationKey(RELATION_OBJECT_ASSIGNEE),
    markedBy: buildRefRelationKey(RELATION_OBJECT_MARKING),
    labelledBy: buildRefRelationKey(RELATION_OBJECT_LABEL),
    creator: 'creator_id',
  },
  Mutation: {
    threatActorGroupEdit: (_, { id }, context) => ({
      delete: () => stixDomainObjectDelete(context, context.user, id),
      fieldPatch: ({ input, commitMessage, references }) => stixDomainObjectEditField(context, context.user, id, input, { commitMessage, references }),
      contextPatch: ({ input }) => stixDomainObjectEditContext(context, context.user, id, input),
      contextClean: () => stixDomainObjectCleanContext(context, context.user, id),
      relationAdd: ({ input }) => stixDomainObjectAddRelation(context, context.user, id, input),
      relationDelete: ({ toId, relationship_type: relationshipType }) => stixDomainObjectDeleteRelation(context, context.user, id, toId, relationshipType),
    }),
    threatActorGroupAdd: (_, { input }, context) => addThreatActorGroup(context, context.user, input),
  },
};

export default threatActorGroupResolvers;
