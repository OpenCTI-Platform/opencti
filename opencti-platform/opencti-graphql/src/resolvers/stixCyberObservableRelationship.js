import { withFilter } from 'graphql-subscriptions';
import { BUS_TOPICS } from '../config/conf';
import {
  addStixCyberObservableRelationship,
  findAll,
  findById,
  stixCyberObservableRelationshipCleanContext,
  stixCyberObservableRelationshipDelete,
  stixCyberObservableRelationshipEditContext,
  stixCyberObservableRelationshipEditField,
  batchNotes,
  batchOpinions,
  batchReports
} from '../domain/stixCyberObservableRelationship';
import { fetchEditContext, pubSubAsyncIterator } from '../database/redis';
import withCancel from '../graphql/subscriptionWrapper';
import { batchLoader } from '../database/middleware';
import { ABSTRACT_STIX_CYBER_OBSERVABLE_RELATIONSHIP } from '../schema/general';
import { elBatchIds } from '../database/engine';
import { batchCreators } from '../domain/user';

const loadByIdLoader = batchLoader(elBatchIds);
const notesLoader = batchLoader(batchNotes);
const opinionsLoader = batchLoader(batchOpinions);
const reportsLoader = batchLoader(batchReports);
const creatorsLoader = batchLoader(batchCreators);

const stixCyberObservableRelationshipResolvers = {
  Query: {
    stixCyberObservableRelationship: (_, { id }, context) => findById(context, context.user, id),
    stixCyberObservableRelationships: (_, args, context) => findAll(context, context.user, args),
  },
  StixCyberObservableRelationship: {
    from: (rel, _, context) => loadByIdLoader.load(rel.fromId, context, context.user),
    to: (rel, _, context) => loadByIdLoader.load(rel.toId, context, context.user),
    reports: (rel, _, context) => reportsLoader.load(rel.id, context, context.user),
    notes: (rel, _, context) => notesLoader.load(rel.id, context, context.user),
    opinions: (rel, _, context) => opinionsLoader.load(rel.id, context, context.user),
    creators: (rel, _, context) => creatorsLoader.load(rel.creator_id, context, context.user),
    editContext: (rel) => fetchEditContext(rel.id),
  },
  Mutation: {
    stixCyberObservableRelationshipEdit: (_, { id }, context) => ({
      delete: () => stixCyberObservableRelationshipDelete(context, context.user, id),
      fieldPatch: ({ input }) => stixCyberObservableRelationshipEditField(context, context.user, id, input),
      contextPatch: ({ input }) => stixCyberObservableRelationshipEditContext(context, context.user, id, input),
      contextClean: () => stixCyberObservableRelationshipCleanContext(context, context.user, id),
    }),
    stixCyberObservableRelationshipAdd: (_, { input }, context) => addStixCyberObservableRelationship(context, context.user, input),
  },
  Subscription: {
    stixCyberObservableRelationship: {
      resolve: /* istanbul ignore next */ (payload) => payload.instance,
      subscribe: /* istanbul ignore next */ (_, { id }, context) => {
        stixCyberObservableRelationshipEditContext(context, context.user, id);
        const filtering = withFilter(
          () => pubSubAsyncIterator(BUS_TOPICS[ABSTRACT_STIX_CYBER_OBSERVABLE_RELATIONSHIP].EDIT_TOPIC),
          (payload) => {
            if (!payload) return false; // When disconnect, an empty payload is dispatched.
            return payload.user.id !== context.user.id && payload.instance.id === id;
          }
        )(_, { id }, context);
        return withCancel(filtering, () => {
          stixCyberObservableRelationshipCleanContext(context, context.user, id);
        });
      },
    },
  },
};

export default stixCyberObservableRelationshipResolvers;
