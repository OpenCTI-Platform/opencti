import { addThreatActorIndividual, findAll, findById, } from './threatActorIndividual-domain';
import {
  stixDomainObjectAddRelation,
  stixDomainObjectCleanContext,
  stixDomainObjectDelete,
  stixDomainObjectDeleteRelation,
  stixDomainObjectEditContext,
  stixDomainObjectEditField
} from '../../domain/stixDomainObject';
import type { Resolvers } from '../../generated/graphql';
import { batchLoader } from '../../database/middleware';
import { batchBornIn, batchEthnicity } from '../../domain/stixCoreObject';
import { utcDate } from '../../utils/format';

const bornInLoader = batchLoader(batchBornIn);
const ethnicityLoader = batchLoader(batchEthnicity);

const threatActorIndividualResolvers: Resolvers = {
  Query: {
    threatActorIndividual: (_, { id }, context) => findById(context, context.user, id),
    threatActorsIndividuals: (_, args, context) => findAll(context, context.user, args),
  },
  ThreatActorIndividual: {
    bornIn: (threatActorIndividual, _, context) => bornInLoader.load(threatActorIndividual.id, context, context.user),
    ethnicity: (threatActorIndividual, _, context) => ethnicityLoader.load(threatActorIndividual.id, context, context.user),
    height: (threatActorIndividual, _, __) => (threatActorIndividual.height ?? [])
      .map((height, index) => ({ ...height, index }))
      .sort((a, b) => utcDate(a.date_seen).diff(utcDate(b.date_seen))),
    weight: (threatActorIndividual, _, __) => (threatActorIndividual.weight ?? [])
      .map((weight, index) => ({ ...weight, index }))
      .sort((a, b) => utcDate(a.date_seen).diff(utcDate(b.date_seen))),
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
