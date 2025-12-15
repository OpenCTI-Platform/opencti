import {
  addStixRefRelationship,
  findRefRelationshipsPaginated,
  findById,
  findNestedPaginated,
  isDatable,
  schemaRefRelationships,
  schemaRefRelationshipsPossibleTypes,
  stixRefRelationshipCleanContext,
  stixRefRelationshipDelete,
  stixRefRelationshipEditContext,
  stixRefRelationshipEditField,
  stixRefRelationshipsNumber,
} from '../domain/stixRefRelationship';
import { fetchEditContext } from '../database/redis';
import { BUS_TOPICS } from '../config/conf';
import { ABSTRACT_STIX_REF_RELATIONSHIP } from '../schema/general';
import { subscribeToInstanceEvents } from '../graphql/subscriptionWrapper';
import { distributionRelations } from '../database/middleware';
import { schemaRelationsRefTypesMapping } from '../database/stix-ref';
import { containersPaginated, notesPaginated, opinionsPaginated, reportsPaginated } from '../domain/stixCoreObject';
import { filterMembersUsersWithUsersOrgs } from '../utils/access';

const stixRefRelationshipResolvers = {
  Query: {
    stixRefRelationship: (_, { id }, context) => findById(context, context.user, id),
    stixRefRelationships: (_, args, context) => findRefRelationshipsPaginated(context, context.user, args),
    stixNestedRefRelationships: (_, args, context) => findNestedPaginated(context, context.user, args),
    stixSchemaRefRelationships: (_, { id, toType }, context) => schemaRefRelationships(context, context.user, id, toType),
    stixSchemaRefRelationshipsPossibleTypes: (_, { type }, context) => schemaRefRelationshipsPossibleTypes(context, context.user, type),
    stixRefRelationshipsDistribution: (_, args, context) => distributionRelations(context, context.user, args),
    stixRefRelationshipsNumber: (_, args, context) => stixRefRelationshipsNumber(context, context.user, args),
    schemaRelationsRefTypesMapping: () => schemaRelationsRefTypesMapping(),
  },
  StixRefRelationship: {
    from: (rel, _, context) => (rel.from ? rel.from : context.batch.idsBatchLoader.load({ id: rel.fromId, type: rel.fromType })),
    to: (rel, _, context) => (rel.to ? rel.to : context.batch.idsBatchLoader.load({ id: rel.toId, type: rel.toType })),
    // region inner listing - cant be batch loaded
    containers: (rel, args, context) => containersPaginated(context, context.user, rel.id, args),
    reports: (rel, args, context) => reportsPaginated(context, context.user, rel.id, args),
    notes: (rel, args, context) => notesPaginated(context, context.user, rel.id, args),
    opinions: (rel, args, context) => opinionsPaginated(context, context.user, rel.id, args),
    creators: async (rel, _, context) => {
      const creators = await context.batch.creatorsBatchLoader.load(rel.creator_id);
      if (!creators) {
        return [];
      }
      return filterMembersUsersWithUsersOrgs(context, context.user, creators);
    },
    // endregion
    // Utils
    editContext: (rel) => fetchEditContext(rel.id),
    datable: (rel) => isDatable(rel.fromType, rel.relationship_type),
  },
  Mutation: {
    stixRefRelationshipEdit: (_, { id }, context) => ({
      delete: () => stixRefRelationshipDelete(context, context.user, id),
      fieldPatch: ({ input }) => stixRefRelationshipEditField(context, context.user, id, input),
      contextPatch: ({ input }) => stixRefRelationshipEditContext(context, context.user, id, input),
    }),
    stixRefRelationshipAdd: (_, { input }, context) => addStixRefRelationship(context, context.user, input),
  },
  Subscription: {
    stixRefRelationship: {
      resolve: /* v8 ignore next */ (payload) => payload.instance,
      subscribe: /* v8 ignore next */ (_, { id }, context) => {
        const preFn = () => stixRefRelationshipEditContext(context, context.user, id);
        const cleanFn = () => stixRefRelationshipCleanContext(context, context.user, id);
        const bus = BUS_TOPICS[ABSTRACT_STIX_REF_RELATIONSHIP];
        return subscribeToInstanceEvents(_, context, id, [bus.EDIT_TOPIC], { type: ABSTRACT_STIX_REF_RELATIONSHIP, preFn, cleanFn });
      },
    },
  },
};

export default stixRefRelationshipResolvers;
