import { withFilter } from 'graphql-subscriptions';
import nconf from 'nconf';
import { BUS_TOPICS } from '../config/conf';
import {
  getSettings,
  settingsEditField,
  settingsEditContext,
  settingsCleanContext,
  getApplicationInfo,
} from '../domain/settings';
import { fetchEditContext, pubsub } from '../database/redis';
import withCancel from '../graphql/subscriptionWrapper';
import { PROVIDERS } from '../config/providers';

const settingsResolvers = {
  Query: {
    about: () => getApplicationInfo(),
    settings: () => getSettings(),
  },
  Settings: {
    platform_providers: () => PROVIDERS,
    platform_demo: () => nconf.get('app:platform_demo') || false,
    editContext: (settings) => fetchEditContext(settings.id),
  },
  Mutation: {
    settingsEdit: (_, { id }, { user }) => ({
      fieldPatch: ({ input }) => settingsEditField(user, id, input),
      contextPatch: ({ input }) => settingsEditContext(user, id, input),
      contextClean: () => settingsCleanContext(user, id),
    }),
  },
  Subscription: {
    settings: {
      resolve: /* istanbul ignore next */ (payload) => payload.instance,
      subscribe: /* istanbul ignore next */ (_, { id }, { user }) => {
        settingsEditContext(user, id);
        const filtering = withFilter(
          () => pubsub.asyncIterator(BUS_TOPICS.Settings.EDIT_TOPIC),
          (payload) => {
            if (!payload) return false; // When disconnect, an empty payload is dispatched.
            return payload.user.id !== user.id && payload.instance.id === id;
          }
        )(_, { id }, { user });
        return withCancel(filtering, () => {
          settingsCleanContext(user, id);
        });
      },
    },
  },
};

export default settingsResolvers;
