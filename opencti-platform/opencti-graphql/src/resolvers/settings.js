import nconf from 'nconf';
import { BUS_TOPICS } from '../config/conf';
import {
  getApplicationDependencies,
  getApplicationInfo,
  getCriticalAlerts,
  getMemoryStatistics,
  getMessagesFilteredByRecipients,
  getSettings,
  settingDeleteMessage,
  settingEditMessage,
  settingsCleanContext,
  settingsEditContext,
  settingsEditField
} from '../domain/settings';
import { fetchEditContext } from '../database/redis';
import { subscribeToInstanceEvents, subscribeToPlatformSettingsEvents } from '../graphql/subscriptionWrapper';
import { ENTITY_TYPE_SETTINGS } from '../schema/internalObject';
import { elAggregationCount } from '../database/engine';
import { findById } from '../modules/organization/organization-domain';
import { READ_DATA_INDICES } from '../database/utils';
import { internalFindByIds } from '../database/middleware-loader';

const settingsResolvers = {
  Query: {
    about: () => getApplicationInfo(),
    settings: (_, __, context) => getSettings(context),
  },
  AppDebugStatistics: {
    objects: (_, __, context) => elAggregationCount(context, context.user, READ_DATA_INDICES, { types: ['Stix-Object'], field: 'entity_type' }),
    relationships: (_, __, context) => elAggregationCount(context, context.user, READ_DATA_INDICES, { types: ['stix-relationship'], field: 'entity_type' }),
  },
  Settings: {
    platform_session_idle_timeout: () => Number(nconf.get('app:session_idle_timeout')),
    platform_session_timeout: () => Number(nconf.get('app:session_timeout')),
    platform_organization: (settings, __, context) => findById(context, context.user, settings.platform_organization),
    platform_critical_alerts: (_, __, context) => getCriticalAlerts(context, context.user),
    activity_listeners: (settings, __, context) => internalFindByIds(context, context.user, settings.activity_listeners_ids),
    otp_mandatory: (settings) => settings.otp_mandatory ?? false,
    password_policy_min_length: (settings) => settings.password_policy_min_length ?? 0,
    password_policy_max_length: (settings) => settings.password_policy_max_length ?? 0,
    password_policy_min_symbols: (settings) => settings.password_policy_min_symbols ?? 0,
    password_policy_min_numbers: (settings) => settings.password_policy_min_numbers ?? 0,
    password_policy_min_words: (settings) => settings.password_policy_min_words ?? 0,
    password_policy_min_lowercase: (settings) => settings.password_policy_min_lowercase ?? 0,
    password_policy_min_uppercase: (settings) => settings.password_policy_min_uppercase ?? 0,
    editContext: (settings) => fetchEditContext(settings.id),
    platform_messages: (settings, _, context) => getMessagesFilteredByRecipients(context.user, settings),
    messages_administration: (settings) => JSON.parse(settings.platform_messages ?? '[]'),
  },
  AppInfo: {
    memory: getMemoryStatistics(),
    dependencies: (_, __, context) => getApplicationDependencies(context)
  },
  SettingsMessage: {
    recipients: (message, _, context) => internalFindByIds(context, context.user, message.recipients),
  },
  Mutation: {
    settingsEdit: (_, { id }, context) => ({
      fieldPatch: ({ input }) => settingsEditField(context, context.user, id, input),
      contextPatch: ({ input }) => settingsEditContext(context, context.user, id, input),
      contextClean: () => settingsCleanContext(context, context.user, id),
      editMessage: ({ input }) => settingEditMessage(context, context.user, id, input),
      deleteMessage: ({ input }) => settingDeleteMessage(context, context.user, id, input),
    }),
  },
  Subscription: {
    settings: {
      resolve: /* v8 ignore next */ (payload) => payload.instance,
      subscribe: /* v8 ignore next */ (_, { id }, context) => {
        const preFn = () => settingsEditContext(context, context.user, id);
        const cleanFn = () => settingsCleanContext(context, context.user, id);
        const bus = BUS_TOPICS[ENTITY_TYPE_SETTINGS];
        return subscribeToInstanceEvents(_, context, id, [bus.EDIT_TOPIC], { preFn, cleanFn });
      },
    },
    settingsMessages: {
      resolve: /* v8 ignore next */ (payload) => payload.instance,
      subscribe: /* v8 ignore next */ async (_, __, context) => {
        return subscribeToPlatformSettingsEvents(context);
      },
    }
  },
};

export default settingsResolvers;
