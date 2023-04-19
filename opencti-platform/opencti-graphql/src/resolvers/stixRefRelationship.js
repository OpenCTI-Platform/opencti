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
import { batchNotes, batchOpinions, batchReports } from '../domain/stixCoreRelationship';
import { batchCreators } from '../domain/user';

const loadByIdLoader = batchLoader(elBatchIds);
const notesLoader = batchLoader(batchNotes);
const opinionsLoader = batchLoader(batchOpinions);
const reportsLoader = batchLoader(batchReports);
const creatorsLoader = batchLoader(batchCreators);

const stixRefRelationshipResolvers = {
  Query: {
    stixRefRelationship: (_, { id }, context) => findById(context, context.user, id),
    stixRefRelationships: (_, args, context) => findAll(context, context.user, args),
    stixNestedRefRelationships: (_, args, context) => findNested(context, context.user, args),
    stixSchemaRefRelationships: (_, { id, toType }, context) => schemaRefRelationships(context, context.user, id, toType),
    stixRefRelationshipsDistribution: (_, args, context) => distributionRelations(context, context.user, args),
    stixRefRelationshipsNumber: (_, args, context) => stixRefRelationshipsNumber(context, context.user, args),
  },
  StixRefRelationship: {
    from: (rel, _, context) => loadByIdLoader.load(rel.fromId, context, context.user),
    to: (rel, _, context) => loadByIdLoader.load(rel.toId, context, context.user),
    reports: (rel, _, context) => reportsLoader.load(rel.id, context, context.user),
    notes: (rel, _, context) => notesLoader.load(rel.id, context, context.user),
    opinions: (rel, _, context) => opinionsLoader.load(rel.id, context, context.user),
    creators: (rel, _, context) => creatorsLoader.load(rel.creator_id, context, context.user),
    editContext: (rel) => fetchEditContext(rel.id),
    datable: (rel) => isDatable(rel.fromType, rel.relationship_type)
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
      resolve: /* istanbul ignore next */ (payload) => payload.instance,
      subscribe: /* istanbul ignore next */ (_, { id }, context) => {
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
