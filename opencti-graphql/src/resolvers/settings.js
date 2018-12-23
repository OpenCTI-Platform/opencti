import { withFilter } from 'graphql-subscriptions';
import { BUS_TOPICS } from '../config/conf';
import {
  getSettings,
  settingsDelete,
  settingsEditField,
  settingsEditContext,
  settingsCleanContext,
  addSettings
} from '../domain/settings';
import { fetchEditContext, pubsub } from '../database/redis';
import { auth, withCancel } from './wrapper';

const settingsResolvers = {
  Query: {
    settings: () => getSettings()
  },
  Settings: {
    editContext: auth(settings => fetchEditContext(settings.id))
  },
  Mutation: {
    settingsEdit: auth((_, { id }, { user }) => ({
      delete: () => settingsDelete(id),
      fieldPatch: ({ input }) => settingsEditField(user, id, input),
      contextPatch: ({ input }) => settingsEditContext(user, id, input)
    })),
    settingsAdd: auth((_, { input }, { user }) => addSettings(user, input))
  },
  Subscription: {
    settings: {
      resolve: payload => payload.instance,
      subscribe: auth((_, { id }, { user }) => {
        settingsEditContext(user, id);
        const filtering = withFilter(
          () => pubsub.asyncIterator(BUS_TOPICS.Settings.EDIT_TOPIC),
          payload => {
            if (!payload) return false; // When disconnect, an empty payload is dispatched.
            return payload.user.id !== user.id;
          }
        )(_, { id }, { user });
        return withCancel(filtering, () => {
          settingsCleanContext(user, id);
        });
      })
    }
  }
};

export default settingsResolvers;
