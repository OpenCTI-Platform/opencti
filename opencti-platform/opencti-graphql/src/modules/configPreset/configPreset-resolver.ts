import type { Resolvers, ResolversTypes } from '../../generated/graphql';
import { configPresetExport, findConfigPresetExportableTypes } from './configPreset-domain';

const configPresetResolvers: Resolvers = {
  Query: {
    configPresetExportableTypes: (_, __, context) => findConfigPresetExportableTypes(context, context.user!),
  },
  Mutation: {
    configPresetExport: async (_, { selections, bundle_name }, context) => {
      const file = await configPresetExport(context, context.user!, selections, bundle_name);
      return file as unknown as ResolversTypes['File'];
    },
  },
};

export default configPresetResolvers;
