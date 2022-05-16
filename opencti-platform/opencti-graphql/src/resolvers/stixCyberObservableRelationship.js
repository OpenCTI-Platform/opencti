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
import { fetchEditContext, pubsub } from '../database/redis';
import withCancel from '../graphql/subscriptionWrapper';
import { batchLoader } from '../database/middleware';
import { ABSTRACT_STIX_CYBER_OBSERVABLE_RELATIONSHIP } from '../schema/general';
import { elBatchIds } from '../database/engine';

const loadByIdLoader = batchLoader(elBatchIds);
const notesLoader = batchLoader(batchNotes);
const opinionsLoader = batchLoader(batchOpinions);
const reportsLoader = batchLoader(batchReports);

const stixCyberObservableRelationshipResolvers = {
  Query: {
    stixCyberObservableRelationship: (_, { id }, { user }) => findById(user, id),
    stixCyberObservableRelationships: (_, args, { user }) => findAll(user, args),
  },
  StixCyberObservableRelationship: {
    from: (rel, _, { user }) => loadByIdLoader.load(rel.fromId, user),
    to: (rel, _, { user }) => loadByIdLoader.load(rel.toId, user),
    reports: (rel, _, { user }) => reportsLoader.load(rel.id, user),
    notes: (rel, _, { user }) => notesLoader.load(rel.id, user),
    opinions: (rel, _, { user }) => opinionsLoader.load(rel.id, user),
    editContext: (rel) => fetchEditContext(rel.id),
  },
  Mutation: {
    stixCyberObservableRelationshipEdit: (_, { id }, { user }) => ({
      delete: () => stixCyberObservableRelationshipDelete(user, id),
      fieldPatch: ({ input }) => stixCyberObservableRelationshipEditField(user, id, input),
      contextPatch: ({ input }) => stixCyberObservableRelationshipEditContext(user, id, input),
      contextClean: () => stixCyberObservableRelationshipCleanContext(user, id),
    }),
    stixCyberObservableRelationshipAdd: (_, { input }, { user }) => addStixCyberObservableRelationship(user, input),
  },
  Subscription: {
    stixCyberObservableRelationship: {
      resolve: /* istanbul ignore next */ (payload) => payload.instance,
      subscribe: /* istanbul ignore next */ (_, { id }, { user }) => {
        stixCyberObservableRelationshipEditContext(user, id);
        const filtering = withFilter(
          () => pubsub.asyncIterator(BUS_TOPICS[ABSTRACT_STIX_CYBER_OBSERVABLE_RELATIONSHIP].EDIT_TOPIC),
          (payload) => {
            if (!payload) return false; // When disconnect, an empty payload is dispatched.
            return payload.user.id !== user.id && payload.instance.id === id;
          }
        )(_, { id }, { user });
        return withCancel(filtering, () => {
          stixCyberObservableRelationshipCleanContext(user, id);
        });
      },
    },
  },
};

export default stixCyberObservableRelationshipResolvers;
