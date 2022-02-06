import { withFilter } from 'graphql-subscriptions';
import nconf from 'nconf';
import { BUS_TOPICS } from '../config/conf';
import {
  getSettings,
  settingsEditField,
  settingsEditContext,
  settingsCleanContext,
  getApplicationInfo,
  getModules,
} from '../domain/settings';
import { fetchEditContext, pubsub } from '../database/redis';
import withCancel from '../graphql/subscriptionWrapper';
import { PROVIDERS } from '../config/providers';
import { ENTITY_TYPE_SETTINGS } from '../schema/internalObject';
import { elAggregationCount } from '../database/engine';

const settingsResolvers = {
  Query: {
    about: () => getApplicationInfo(),
    settings: () => getSettings(),
  },
  AppDebugStatistics: {
    objects: (_, __, { user }) => elAggregationCount(user, 'Stix-Object', 'entity_type'),
    relationships: (_, __, { user }) => elAggregationCount(user, 'stix-relationship', 'entity_type'),
  },
  Settings: {
    platform_providers: () => PROVIDERS,
    platform_modules: () => getModules(),
    platform_map_tile_server_dark: () => nconf.get('app:map_tile_server_dark'),
    platform_map_tile_server_light: () => nconf.get('app:map_tile_server_light'),
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
