import { addIntrusionSet, findAll, findById, batchLocations } from '../domain/intrusionSet';
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
} from '../schema/stixMetaRelationship';
import { buildRefRelationKey } from '../schema/general';
import { batchLoader } from '../database/middleware';

const locationsLoader = batchLoader(batchLocations);

const intrusionSetResolvers = {
  Query: {
    intrusionSet: (_, { id }, context) => findById(context, context.user, id),
    intrusionSets: (_, args, context) => findAll(context, context.user, args),
  },
  IntrusionSet: {
    locations: (intrusionSet, _, context) => locationsLoader.load(intrusionSet.id, context, context.user),
  },
  IntrusionSetsFilter: {
    createdBy: buildRefRelationKey(RELATION_CREATED_BY),
    markedBy: buildRefRelationKey(RELATION_OBJECT_MARKING),
    assigneeTo: buildRefRelationKey(RELATION_OBJECT_ASSIGNEE),
    labelledBy: buildRefRelationKey(RELATION_OBJECT_LABEL),
    creator: 'creator_id',
  },
  Mutation: {
    intrusionSetEdit: (_, { id }, context) => ({
      delete: () => stixDomainObjectDelete(context, context.user, id),
      fieldPatch: ({ input, commitMessage, references }) => stixDomainObjectEditField(context, context.user, id, input, { commitMessage, references }),
      contextPatch: ({ input }) => stixDomainObjectEditContext(context, context.user, id, input),
      contextClean: () => stixDomainObjectCleanContext(context, context.user, id),
      relationAdd: ({ input }) => stixDomainObjectAddRelation(context, context.user, id, input),
      relationDelete: ({ toId, relationship_type: relationshipType }) => stixDomainObjectDeleteRelation(context, context.user, id, toId, relationshipType),
    }),
    intrusionSetAdd: (_, { input }, context) => addIntrusionSet(context, context.user, input),
  },
};

export default intrusionSetResolvers;
