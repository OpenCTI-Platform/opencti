import {
  addThreatActorIndividual, batchCountries, batchLocations,
  findAll, findById,
} from './threatActorIndividual-domain';
import { batchLoader } from '../../database/middleware';
import { buildRefRelationKey } from '../../schema/general';
import {
  RELATION_CREATED_BY,
  RELATION_OBJECT_ASSIGNEE, RELATION_OBJECT_LABEL,
  RELATION_OBJECT_MARKING
} from '../../schema/stixRefRelationship';
import type { BasicStoreEntityThreatActorIndividual } from './threatActorIndividual-types';
import {
  stixDomainObjectAddRelation,
  stixDomainObjectCleanContext,
  stixDomainObjectDelete, stixDomainObjectDeleteRelation,
  stixDomainObjectEditContext,
  stixDomainObjectEditField
} from '../../domain/stixDomainObject';
import type { Resolvers } from '../../generated/graphql';

const locationsLoader = batchLoader(batchLocations);
const countriesLoader = batchLoader(batchCountries);

const threatActorIndividualResolvers: Resolvers = {
  Query: {
    threatActorIndividual: (_, { id }, context) => findById(context, context.user, id),
    threatActorsIndividuals: (_, args, context) => findAll(context, context.user, args),
  },
  threatActorIndividual: {
    locations: (threatActorIndividual: BasicStoreEntityThreatActorIndividual, _, context) => locationsLoader.load(threatActorIndividual.id, context, context.user),
    countries: (threatActorIndividual: BasicStoreEntityThreatActorIndividual, _, context) => countriesLoader.load(threatActorIndividual.id, context, context.user),
  },
  threatActorsIndividualFilter: {
    createdBy: buildRefRelationKey(RELATION_CREATED_BY),
    assigneeTo: buildRefRelationKey(RELATION_OBJECT_ASSIGNEE),
    markedBy: buildRefRelationKey(RELATION_OBJECT_MARKING),
    labelledBy: buildRefRelationKey(RELATION_OBJECT_LABEL),
    creator: 'creator_id',
  },
  Mutation: {
    threatActorIndividualAdd: (_, { input }, context) => {
      return addThreatActorIndividual(context, context.user, input);
    },
    threatActorIndividualDelete: (_, { id }, context) => {
      return stixDomainObjectDelete(context, context.user, id);
    },
    threatActorIndividualFieldPatch: (_, { id, input }, context) => {
      return stixDomainObjectEditField(context, context.user, id, input);
    },
    threatActorIndividualContextPatch: (_, { id, input }, context) => {
      return stixDomainObjectEditContext(context, context.user, id, input);
    },
    threatActorIndividualContextClean: (_, { id }, context) => {
      return stixDomainObjectCleanContext(context, context.user, id);
    },
    threatActorIndividualRelationAdd: (_, { id, input }, context) => {
      return stixDomainObjectAddRelation(context, context.user, id, input);
    },
    threatActorIndividualRelationDelete: (_, { id, toId, relationship_type: relationshipType }, context) => {
      return stixDomainObjectDeleteRelation(context, context.user, id, toId, relationshipType);
    },
  },
};

export default threatActorIndividualResolvers;
