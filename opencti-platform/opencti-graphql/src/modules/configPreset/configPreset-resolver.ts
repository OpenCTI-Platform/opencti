import type { Resolvers, ResolversTypes } from '../../generated/graphql';
import { configPresetExport, findConfigPresetExportableItems, findConfigPresetExportableTypes } from './configPreset-domain';
import { configPresetImportPreview, configPresetImportUpload } from './configPreset-import-domain';
import { clearConfigPresetImportSession, findConfigPresetImportSession, saveConfigPresetImportSession } from './configPreset-import-session-domain';

const configPresetResolvers: Resolvers = {
  Query: {
    configPresetExportableTypes: (_, __, context) => findConfigPresetExportableTypes(context, context.user!),
    configPresetExportableItems: (_, args, context) => findConfigPresetExportableItems(context, context.user!, args),
    configPresetImportPreview: (_, { file_id }, context) => configPresetImportPreview(context, context.user!, file_id),
    configPresetImportSession: (_, __, context) => findConfigPresetImportSession(context, context.user!) as never,
  },
  Mutation: {
    configPresetExport: async (_, { selections, bundle_name }, context) => {
      const file = await configPresetExport(context, context.user!, selections, bundle_name);
      return file as unknown as ResolversTypes['File'];
    },
    configPresetImportSessionSave: (_, { file_id, selections, revision }, context) => {
      return saveConfigPresetImportSession(context, context.user!, file_id, selections, revision) as never;
    },
    configPresetImportSessionClear: (_, { delete_file }, context) => clearConfigPresetImportSession(context, context.user!, delete_file ?? false),
    configPresetImportUpload: async (_, { file }, context) => {
      const upload = await configPresetImportUpload(context, context.user!, file);
      return upload as unknown as ResolversTypes['File'];
    },
  },
};

export default configPresetResolvers;
