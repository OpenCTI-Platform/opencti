import type { Resolvers } from '../../generated/graphql';
import { findById, findByManagerId, managerConfigurationEditField } from './managerConfiguration-domain';
import { BUS_TOPICS } from '../../config/conf';
import { ENTITY_TYPE_MANAGER_CONFIGURATION } from './managerConfiguration-types';
import { supportedMimeTypes } from './managerConfiguration-utils';
import { subscribeToInstanceEvents } from '../../graphql/subscriptionWrapper';

const managerConfigurationResolvers: Resolvers = {
  Query: {
    managerConfiguration: (_, { id }, context) => findById(context, context.user, id),
    managerConfigurationByManagerId: (_, { managerId }, context) => findByManagerId(context, context.user, managerId),
  },
  Mutation: {
    managerConfigurationFieldPatch: (_, { id, input }, context) => {
      return managerConfigurationEditField(context, context.user, id, input);
    },
  },
  ManagerConfiguration: {
    manager_setting: (config) => {
      // For index manager, inject the supported mime types
      if (config.manager_id === 'FILE_INDEX_MANAGER') {
        const setting = config.manager_setting;
        setting.supported_mime_types = supportedMimeTypes;
        setting.max_file_size = Math.floor(setting.max_file_size / (1024 * 1024));
        return setting;
      }
      return config.manager_setting;
    }
  },
  Subscription: {
    managerConfiguration: {
      resolve: /* v8 ignore next */ (payload: any) => {
        return payload.instance;
      },
      subscribe: /* v8 ignore next */ (_, { id }, context) => {
        const bus = BUS_TOPICS[ENTITY_TYPE_MANAGER_CONFIGURATION];
        return subscribeToInstanceEvents(_, context, id, [bus.EDIT_TOPIC], { type: ENTITY_TYPE_MANAGER_CONFIGURATION, notifySelf: true });
      },
    },
  }
};

export default managerConfigurationResolvers;
