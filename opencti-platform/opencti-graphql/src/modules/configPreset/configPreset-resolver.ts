import type { Resolvers } from '../../generated/graphql';
import { findConfigPresetExportableTypes } from './configPreset-domain';

const configPresetResolvers: Resolvers = {
  Query: {
    configPresetExportableTypes: (_, __, context) => findConfigPresetExportableTypes(context, context.user!),
  },
};

export default configPresetResolvers;
