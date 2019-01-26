import { withFilter } from 'graphql-subscriptions';
import { BUS_TOPICS } from '../config/conf';
import {
  addOrganization,
  organizationDelete,
  findAll,
  findById,
  markingDefinitions,
  organizationEditContext,
  organizationEditField,
  organizationAddRelation,
  organizationDeleteRelation,
  organizationCleanContext
} from '../domain/organization';
import { fetchEditContext, pubsub } from '../database/redis';
import { auth, withCancel } from './wrapper';

const organizationResolvers = {
  Query: {
    organization: auth((_, { id }) => findById(id)),
    organizations: auth((_, args) => findAll(args))
  },
  Organization: {
    markingDefinitions: (organization, args) =>
      markingDefinitions(organization.id, args),
    editContext: auth(organization => fetchEditContext(organization.id))
  },
  Mutation: {
    organizationEdit: auth((_, { id }, { user }) => ({
      delete: () => organizationDelete(id),
      fieldPatch: ({ input }) => organizationEditField(user, id, input),
      contextPatch: ({ input }) => organizationEditContext(user, id, input),
      relationAdd: ({ input }) => organizationAddRelation(user, id, input),
      relationDelete: ({ relationId }) =>
        organizationDeleteRelation(user, id, relationId)
    })),
    organizationAdd: auth((_, { input }, { user }) => addOrganization(user, input))
  },
  Subscription: {
    organization: {
      resolve: payload => payload.instance,
      subscribe: auth((_, { id }, { user }) => {
        organizationEditContext(user, id);
        const filtering = withFilter(
          () => pubsub.asyncIterator(BUS_TOPICS.Organization.EDIT_TOPIC),
          payload => {
            if (!payload) return false; // When disconnect, an empty payload is dispatched.
            return payload.user.id !== user.id && payload.instance.id === id;
          }
        )(_, { id }, { user });
        return withCancel(filtering, () => {
          organizationCleanContext(user, id);
        });
      })
    }
  }
};

export default organizationResolvers;
