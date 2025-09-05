import type { Resolvers } from '../../generated/graphql';
import { addNarrative, childNarrativesPaginated, findNarrativePaginated, findById, isSubNarrative, parentNarrativesPaginated } from './narrative-domain';
import {
  stixDomainObjectAddRelation,
  stixDomainObjectCleanContext,
  stixDomainObjectDelete,
  stixDomainObjectDeleteRelation,
  stixDomainObjectEditContext,
  stixDomainObjectEditField
} from '../../domain/stixDomainObject';
import type { BasicStoreEntityNarrative } from './narrative-types';

const narrativeResolvers: Resolvers = {
  Query: {
    narrative: (_, { id }, context) => findById(context, context.user, id),
    narratives: (_, args, context) => findNarrativePaginated(context, context.user, args),
  },
  Narrative: {
    parentNarratives: (narrative, args, context) => parentNarrativesPaginated<BasicStoreEntityNarrative>(context, context.user, narrative.id, args),
    subNarratives: (narrative, args, context) => childNarrativesPaginated<BasicStoreEntityNarrative>(context, context.user, narrative.id, args),
    isSubNarrative: (narrative, _, context) => isSubNarrative(context, context.user, narrative.id),
  },
  Mutation: {
    narrativeAdd: (_, { input }, context) => {
      return addNarrative(context, context.user, input);
    },
    narrativeDelete: (_, { id }, context) => {
      return stixDomainObjectDelete(context, context.user, id);
    },
    narrativeFieldPatch: (_, { id, input, commitMessage, references }, context) => {
      return stixDomainObjectEditField(context, context.user, id, input, { commitMessage, references });
    },
    narrativeContextPatch: (_, { id, input }, context) => {
      return stixDomainObjectEditContext(context, context.user, id, input);
    },
    narrativeContextClean: (_, { id }, context) => {
      return stixDomainObjectCleanContext(context, context.user, id);
    },
    narrativeRelationAdd: (_, { id, input }, context) => {
      return stixDomainObjectAddRelation(context, context.user, id, input);
    },
    narrativeRelationDelete: (_, { id, toId, relationship_type: relationshipType }, context) => {
      return stixDomainObjectDeleteRelation(context, context.user, id, toId, relationshipType);
    },
  },
};

export default narrativeResolvers;
