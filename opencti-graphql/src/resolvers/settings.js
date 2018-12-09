import { BUS_TOPICS } from '../config/conf';
import {
  addSettings,
  settingsDelete,
  findById,
  settingsEditContext,
  settingsEditField,
  settingsAddRelation,
  settingsDeleteRelation,
  settingsCleanContext
} from '../domain/settings';
import { fetchEditContext, pubsub } from '../database/redis';
import { admin, auth, withCancel } from './wrapper';

const settingsResolvers = {
  Query: {
    settings: auth((_, { id }) => findById(id)),
  },
  Settings: {
    editContext: admin(settings => fetchEditContext(settings.id))
  },
  Mutation: {
    settingsEdit: admin((_, { id }, { user }) => ({
      delete: () => settingsDelete(id),
      fieldPatch: ({ input }) => settingsEditField(id, input),
      contextPatch: ({ input }) => settingsEditContext(user, id, input),
      relationAdd: ({ input }) => settingsAddRelation(id, input),
      relationDelete: ({ relationId }) => settingsDeleteRelation(relationId)
    })),
    settingsAdd: admin((_, { input }, { user }) => addSettings(user, input))
  },
  Subscription: {
    settings: {
      resolve: payload => payload.instance,
      subscribe: admin((_, { id }, { user }) => {
        settingsEditContext(user, id);
        return withCancel(
          pubsub.asyncIterator(BUS_TOPICS.Settings.EDIT_TOPIC),
          () => {
            settingsCleanContext(user, id);
          }
        );
      })
    }
  }
};

export default settingsResolvers;
