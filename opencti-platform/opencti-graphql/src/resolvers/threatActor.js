import { findAll as genericFindAll, findById as genericFindById, batchCountries, batchLocations } from '../domain/threatActor';
import { addThreatActorGroup, findAll as groupFindAll, findById as groupFindById } from '../domain/threatActorGroup';
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
    threatActor: (_, { id }, context) => genericFindById(context, context.user, id),
    threatActors: (_, args, context) => genericFindAll(context, context.user, args),
    threatActorGroup: (_, { id }, context) => groupFindById(context, context.user, id),
    threatActorsGroup: (_, args, context) => groupFindAll(context, context.user, args),
  },
  ThreatActorGroup: {
    locations: (threatActorGroup, _, context) => locationsLoader.load(threatActorGroup.id, context, context.user),
    countries: (threatActorGroup, _, context) => countriesLoader.load(threatActorGroup.id, context, context.user),
    __resolveType(obj) {
      if (obj.entity_type) {
        return obj.entity_type.replace(/(?:^|-)(\w)/g, (matches, letter) => letter.toUpperCase());
      }
      return 'Unknown';
    },
  },
  ThreatActorsFilter: {
    createdBy: buildRefRelationKey(RELATION_CREATED_BY),
    assigneeTo: buildRefRelationKey(RELATION_OBJECT_ASSIGNEE),
    markedBy: buildRefRelationKey(RELATION_OBJECT_MARKING),
    labelledBy: buildRefRelationKey(RELATION_OBJECT_LABEL),
    creator: 'creator_id',
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
