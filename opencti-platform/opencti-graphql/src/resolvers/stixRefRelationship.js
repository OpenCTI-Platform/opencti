import { withFilter } from 'graphql-subscriptions';
import {
  addStixRefRelationship,
  findAll,
  findById,
  findNested,
  isDatable,
  schemaRefRelationships,
  stixRefRelationshipCleanContext,
  stixRefRelationshipDelete,
  stixRefRelationshipEditContext,
  stixRefRelationshipEditField,
  stixRefRelationshipsNumber
} from '../domain/stixRefRelationship';
import { fetchEditContext, pubSubAsyncIterator } from '../database/redis';
import { BUS_TOPICS } from '../config/conf';
import { ABSTRACT_STIX_REF_RELATIONSHIP } from '../schema/general';
import withCancel from '../graphql/subscriptionWrapper';
import { batchLoader, distributionRelations } from '../database/middleware';
import { elBatchIds } from '../database/engine';
import { batchCreators } from '../domain/user';
import { schemaRelationsRefTypesMapping } from '../database/stix-ref';
import { containersPaginated, notesPaginated, opinionsPaginated, reportsPaginated } from '../domain/stixCoreObject';

const loadByIdLoader = batchLoader(elBatchIds);
const creatorsLoader = batchLoader(batchCreators);

const stixRefRelationshipResolvers = {
  Query: {
    stixRefRelationship: (_, { id }, context) => findById(context, context.user, id),
    stixRefRelationships: (_, args, context) => findAll(context, context.user, args),
    stixNestedRefRelationships: (_, args, context) => findNested(context, context.user, args),
    stixSchemaRefRelationships: (_, { id, toType }, context) => schemaRefRelationships(context, context.user, id, toType),
    stixRefRelationshipsDistribution: (_, args, context) => distributionRelations(context, context.user, args),
    stixRefRelationshipsNumber: (_, args, context) => stixRefRelationshipsNumber(context, context.user, args),
    schemaRelationsRefTypesMapping: () => schemaRelationsRefTypesMapping(),
  },
  StixRefRelationship: {
    from: (rel, _, context) => (rel.from ? rel.from : loadByIdLoader.load({ id: rel.fromId, type: rel.fromType }, context, context.user)),
    to: (rel, _, context) => (rel.to ? rel.to : loadByIdLoader.load({ id: rel.toId, type: rel.toType }, context, context.user)),
    // region inner listing - cant be batch loaded
    containers: (rel, args, context) => containersPaginated(context, context.user, rel.id, args),
    reports: (rel, args, context) => reportsPaginated(context, context.user, rel.id, args),
    notes: (rel, args, context) => notesPaginated(context, context.user, rel.id, args),
    opinions: (rel, args, context) => opinionsPaginated(context, context.user, rel.id, args),
    creators: (rel, _, context) => creatorsLoader.load(rel.creator_id, context, context.user),
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
        stixRefRelationshipEditContext(context, context.user, id);
        const filtering = withFilter(
          () => pubSubAsyncIterator(BUS_TOPICS[ABSTRACT_STIX_REF_RELATIONSHIP].EDIT_TOPIC),
          (payload) => {
            if (!payload) return false; // When disconnect, an empty payload is dispatched.
            return payload.user.id !== context.user.id && payload.instance.id === id;
          }
        )(_, { id }, context);
        return withCancel(filtering, () => {
          stixRefRelationshipCleanContext(context, context.user, id);
        });
      }
    }
  },
};

export default stixRefRelationshipResolvers;
