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
import { ENTITY_TYPE_SETTINGS } from '../schema/internalObject';

const settingsResolvers = {
  Query: {
    about: () => getApplicationInfo(),
    settings: () => getSettings(),
  },
  Settings: {
    platform_providers: () => PROVIDERS,
    platform_demo: () => nconf.get('app:platform_demo') || false,
    platform_map_tile_server: () =>
      nconf.get('app:map_tile_server') ||
      'https://map.opencti.io/styles/3f7a0834-7061-4cd4-a553-447c7156d88b/{z}/{x}/{y}.png',
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
          () => pubsub.asyncIterator(BUS_TOPICS[ENTITY_TYPE_SETTINGS].EDIT_TOPIC),
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
