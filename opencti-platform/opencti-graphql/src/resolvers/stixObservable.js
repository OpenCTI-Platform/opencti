import { withFilter } from 'graphql-subscriptions';
import { BUS_TOPICS } from '../config/conf';
import {
  addStixObservable,
  stixObservableDelete,
  findAll,
  findById,
  findByValue,
  stixObservablesNumber,
  search,
  markingDefinitions,
  tags,
  reports,
  stixObservablesTimeSeries,
  stixObservableEditContext,
  stixObservableCleanContext,
  stixObservableEditField,
  stixObservableAddRelation,
  stixObservableDeleteRelation,
  stixRelations,
  createdByRef,
  stixObservableAskEnrichment
} from '../domain/stixObservable';
import { fetchEditContext, pubsub } from '../database/redis';
import withCancel from '../schema/subscriptionWrapper';
import { workForEntity } from '../domain/work';
import { connectorsForEnrichment } from '../domain/connector';

const stixObservableResolvers = {
  Query: {
    stixObservable: (_, { id }) => findById(id),
    stixObservables: (_, args) => {
      if (args.search && args.search.length > 0) {
        return search(args);
      }
      if (args.observableValue && args.observableValue.length > 0) {
        return findByValue(args);
      }
      return findAll(args);
    },
    stixObservablesTimeSeries: (_, args) => stixObservablesTimeSeries(args),
    stixObservablesNumber: (_, args) => stixObservablesNumber(args)
  },
  StixObservable: {
    createdByRef: stixObservable => createdByRef(stixObservable.id),
    markingDefinitions: (stixObservable, args) =>
      markingDefinitions(stixObservable.id, args),
    tags: (stixObservable, args) => tags(stixObservable.id, args),
    reports: (stixObservable, args) => reports(stixObservable.id, args),
    stixRelations: (stixObservable, args) =>
      stixRelations(stixObservable.id, args),
    jobs: (stixObservable, args) => workForEntity(stixObservable.id, args),
    connectors: (stixObservable, { onlyAlive = false }) =>
      connectorsForEnrichment(stixObservable.entity_type, onlyAlive),
    editContext: stixObservable => fetchEditContext(stixObservable.id)
  },
  Mutation: {
    stixObservableEdit: (_, { id }, { user }) => ({
      delete: () => stixObservableDelete(id),
      fieldPatch: ({ input }) => stixObservableEditField(user, id, input),
      contextPatch: ({ input }) => stixObservableEditContext(user, id, input),
      contextClean: () => stixObservableCleanContext(user, id),
      relationAdd: ({ input }) => stixObservableAddRelation(user, id, input),
      relationDelete: ({ relationId }) =>
        stixObservableDeleteRelation(user, id, relationId),
      askEnrichment: ({ connectorId }) =>
        stixObservableAskEnrichment(id, connectorId)
    }),
    stixObservableAdd: (_, { input }, { user }) =>
      addStixObservable(user, input)
  },
  Subscription: {
    stixObservable: {
      resolve: payload => payload.instance,
      subscribe: (_, { id }, { user }) => {
        stixObservableEditContext(user, id);
        const filtering = withFilter(
          () => pubsub.asyncIterator(BUS_TOPICS.StixObservable.EDIT_TOPIC),
          payload => {
            if (!payload) return false; // When disconnect, an empty payload is dispatched.
            return payload.user.id !== user.id && payload.instance.id === id;
          }
        )(_, { id }, { user });
        return withCancel(filtering, () => {
          stixObservableCleanContext(user, id);
        });
      }
    }
  }
};

export default stixObservableResolvers;
