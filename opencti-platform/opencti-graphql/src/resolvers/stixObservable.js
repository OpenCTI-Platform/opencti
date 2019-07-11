import { withFilter } from 'graphql-subscriptions';
import { BUS_TOPICS } from '../config/conf';
import {
  addStixObservable,
  stixObservableDelete,
  findAll,
  findById,
  findByValue,
  search,
  markingDefinitions,
  reports,
  stixObservablesTimeSeries,
  stixObservableEditContext,
  stixObservableCleanContext,
  stixObservableEditField,
  stixObservableAddRelation,
  stixObservableDeleteRelation,
  stixRelations,
  createdByRef
} from '../domain/stixObservable';
import { fetchEditContext, pubsub } from '../database/redis';
import withCancel from '../schema/subscriptionWrapper';

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
    stixObservablesTimeSeries: (_, args) =>
      stixObservablesTimeSeries(args)
  },
  StixObservable: {
    createdByRef: (stixObservable, args) =>
      createdByRef(stixObservable.id, args),
    markingDefinitions: (stixObservable, args) =>
      markingDefinitions(stixObservable.id, args),
    reports: (stixObservable, args) => reports(stixObservable.id, args),
    stixRelations: (stixObservable, args) =>
      stixRelations(stixObservable.id, args),
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
        stixObservableDeleteRelation(user, id, relationId)
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
