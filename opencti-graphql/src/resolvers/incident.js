import { withFilter } from 'graphql-subscriptions';
import { BUS_TOPICS } from '../config/conf';
import {
  addIncident,
  incidentDelete,
  findAll,
  findById,
  createdByRef,
  markingDefinitions,
  killChainPhases,
  reports,
  incidentEditContext,
  incidentEditField,
  incidentAddRelation,
  incidentDeleteRelation,
  incidentCleanContext
} from '../domain/incident';
import { fetchEditContext, pubsub } from '../database/redis';
import { auth, withCancel } from './wrapper';

const incidentResolvers = {
  Query: {
    incident: auth((_, { id }) => findById(id)),
    incidents: auth((_, args) => findAll(args))
  },
  Incident: {
    createdByRef: (incident, args) => createdByRef(incident.id, args),
    markingDefinitions: (incident, args) => markingDefinitions(incident.id, args),
    reports: (incident, args) => reports(incident.id, args),
    editContext: auth(incident => fetchEditContext(incident.id))
  },
  Mutation: {
    incidentEdit: auth((_, { id }, { user }) => ({
      delete: () => incidentDelete(id),
      fieldPatch: ({ input }) => incidentEditField(user, id, input),
      contextPatch: ({ input }) => incidentEditContext(user, id, input),
      relationAdd: ({ input }) => incidentAddRelation(user, id, input),
      relationDelete: ({ relationId }) =>
        incidentDeleteRelation(user, id, relationId)
    })),
    incidentAdd: auth((_, { input }, { user }) => addIncident(user, input))
  },
  Subscription: {
    incident: {
      resolve: payload => payload.instance,
      subscribe: auth((_, { id }, { user }) => {
        incidentEditContext(user, id);
        const filtering = withFilter(
          () => pubsub.asyncIterator(BUS_TOPICS.Incident.EDIT_TOPIC),
          payload => {
            if (!payload) return false; // When disconnect, an empty payload is dispatched.
            return payload.user.id !== user.id;
          }
        )(_, { id }, { user });
        return withCancel(filtering, () => {
          incidentCleanContext(user, id);
        });
      })
    }
  }
};

export default incidentResolvers;
