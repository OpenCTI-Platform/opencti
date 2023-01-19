import { withFilter } from 'graphql-subscriptions';
import { BUS_TOPICS } from '../config/conf';
import {
  getApplicationInfo,
  getSettings,
  settingsCleanContext,
  settingsEditContext,
  settingsEditField,
} from '../domain/settings';
import { fetchEditContext, pubsub } from '../database/redis';
import withCancel from '../graphql/subscriptionWrapper';
import { ENTITY_TYPE_SETTINGS } from '../schema/internalObject';
import { elAggregationCount } from '../database/engine';
import { findById } from '../domain/organization';
import { READ_DATA_INDICES } from '../database/utils';

const settingsResolvers = {
  Query: {
    about: (_, __, context) => getApplicationInfo(context),
    settings: (_, __, context) => getSettings(context),
  },
  AppDebugStatistics: {
    objects: (_, __, context) => elAggregationCount(context, context.user, READ_DATA_INDICES, { types: ['Stix-Object'], field: 'entity_type' }),
    relationships: (_, __, context) => elAggregationCount(context, context.user, READ_DATA_INDICES, { types: ['stix-relationship'], field: 'entity_type' }),
  },
  Settings: {
    platform_organization: (settings, __, context) => findById(context, context.user, settings.platform_organization),
    otp_mandatory: (settings) => settings.otp_mandatory ?? false,
    editContext: (settings) => fetchEditContext(settings.id),
  },
  Mutation: {
    settingsEdit: (_, { id }, context) => ({
      fieldPatch: ({ input }) => settingsEditField(context, context.user, id, input),
      contextPatch: ({ input }) => settingsEditContext(context, context.user, id, input),
      contextClean: () => settingsCleanContext(context, context.user, id),
    }),
  },
  Subscription: {
    settings: {
      resolve: /* istanbul ignore next */ (payload) => payload.instance,
      subscribe: /* istanbul ignore next */ (_, { id }, context) => {
        settingsEditContext(context, context.user, id);
        const filtering = withFilter(
          () => pubsub.asyncIterator(BUS_TOPICS[ENTITY_TYPE_SETTINGS].EDIT_TOPIC),
          (payload) => {
            if (!payload) return false; // When disconnect, an empty payload is dispatched.
            return payload.user.id !== context.user.id && payload.instance.id === id;
          }
        )(_, { id }, context);
        return withCancel(filtering, () => {
          settingsCleanContext(context, context.user, id);
        });
      },
    },
  },
};

export default settingsResolvers;
