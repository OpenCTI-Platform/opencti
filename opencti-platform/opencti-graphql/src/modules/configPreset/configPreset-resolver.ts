import type { Resolvers, ResolversTypes } from '../../generated/graphql';
import { configPresetExport, findConfigPresetExportableItems, findConfigPresetExportableTypes } from './export/configPreset-export-domain';
import { configPresetImportPreview, configPresetImportUpload } from './import/configPreset-import-domain';
import { configPresetImport } from './import/configPreset-import-engine';
import {
  backToConfigPresetImportSelection,
  clearConfigPresetImportSession,
  findConfigPresetImportSession,
  saveConfigPresetImportSession,
} from './import/configPreset-import-session-domain';
import { findConfigPresetImportRunning } from './import/configPreset-import-running';
import { getConfigPresetFamilyDisplay } from './configPreset-registry';

const configPresetResolvers: Resolvers = {
  // A result carries the bare family id: the type and the group come from the registry
  ConfigPresetImportResult: {
    label: ({ label, key }) => label ?? key,
    translatable: ({ translatable }) => translatable ?? false,
    type_label: ({ type }) => getConfigPresetFamilyDisplay(type).type_label,
    type_index: ({ type }) => getConfigPresetFamilyDisplay(type).type_index,
    group: ({ type }) => getConfigPresetFamilyDisplay(type).group,
  },
  Query: {
    configPresetExportableTypes: (_, __, context) => findConfigPresetExportableTypes(context, context.user!),
    configPresetExportableItems: (_, args, context) => findConfigPresetExportableItems(context, context.user!, args),
    configPresetImportPreview: (_, { file_id }, context) => configPresetImportPreview(context, context.user!, file_id),
    configPresetImportSession: (_, __, context) => findConfigPresetImportSession(context, context.user!),
    configPresetImportRunning: (_, __, context) => findConfigPresetImportRunning(context, context.user!),
  },
  Mutation: {
    configPresetExport: async (_, { selections, bundle_name }, context) => {
      const file = await configPresetExport(context, context.user!, selections, bundle_name);
      return file as unknown as ResolversTypes['File'];
    },
    configPresetImport: (_, { file_id, selections, dry_run }, context) => configPresetImport(context, context.user!, file_id, selections, dry_run ?? false),
    configPresetImportSessionSave: (_, { file_id, selections, revision }, context) => {
      return saveConfigPresetImportSession(context, context.user!, file_id, selections, revision);
    },
    configPresetImportSessionBackToSelection: (_, __, context) => backToConfigPresetImportSelection(context, context.user!),
    configPresetImportSessionClear: (_, { delete_file }, context) => clearConfigPresetImportSession(context, context.user!, delete_file ?? false),
    configPresetImportUpload: async (_, { file }, context) => {
      const upload = await configPresetImportUpload(context, context.user!, file);
      return upload as unknown as ResolversTypes['File'];
    },
  },
};

export default configPresetResolvers;
