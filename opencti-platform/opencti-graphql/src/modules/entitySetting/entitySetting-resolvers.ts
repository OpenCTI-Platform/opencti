import { entitySettingsEditField, findAll, findById, findByType } from './entitySetting-domain';
import type { Resolvers } from '../../generated/graphql';

const entitySettingResolvers: Resolvers = {
  Query: {
    entitySetting: (_, { id }, context) => findById(context, context.user, id),
    entitySettings: (_, args, context) => findAll(context, context.user, args),
    entitySettingByType: (_, { targetType }, context) => findByType(context, context.user, targetType),
  },
  Mutation: {
    entitySettingsFieldPatch: (_, { ids, input }, context) => {
      return entitySettingsEditField(context, context.user, ids, input);
    },
  },
};

export default entitySettingResolvers;
