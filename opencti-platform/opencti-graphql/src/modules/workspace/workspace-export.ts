import * as R from 'ramda';
import pjson from '../../../package.json';
import { FunctionalError } from '../../config/errors';
import type { AuthContext, AuthUser } from '../../types/user';
import { fromB64, toB64 } from '../../utils/base64';
import { convertDashboardManifestIds, exportDashboardWidget } from '../dashboard/dashboard-utils';
import type { BasicStoreEntityWorkspace } from './workspace-types';

// The manifest of a bundle. The variables travel with it, their ids converted as the ones of the widgets (convertDashboardManifestIds).
// The presets, which are sets of values of the variables, are not part of a bundle
const toBundleManifest = async (context: AuthContext, user: AuthUser, encoded: string) => {
  const manifest = toB64(R.omit(['presets'], fromB64(encoded))) as string;
  return convertDashboardManifestIds(context, user, manifest, 'internal', { keepMissingSavedFilters: true });
};

// A dashboard in the import format (workspace-import-schema). Only what the dashboard is: not who can open it (the users and the groups are not
// the same on another platform, and the file export of a dashboard does not carry them either).
// The ids of the manifest are standard ids.
// A saved filter that does not exist keeps its reference: the widget shows it as missing, as on this platform.
export const exportDashboard = async (context: AuthContext, user: AuthUser, workspace: BasicStoreEntityWorkspace) => {
  const manifest = workspace.manifest ? await toBundleManifest(context, user, workspace.manifest) : undefined;
  return {
    name: workspace.name,
    // Always written, empty or not (0 is no refresh): an overwrite then makes the description, the tags and the refresh interval of the dashboard
    // the ones of the bundle, empty ones included
    description: workspace.description ?? '',
    tags: workspace.tags ?? [],
    refresh_interval: workspace.refresh_interval ?? 0,
    ...(manifest ? { manifest } : {}),
  };
};

export const generateWorkspaceExportConfiguration = async (context: AuthContext, user: AuthUser, workspace: BasicStoreEntityWorkspace) => {
  if (workspace.type !== 'dashboard') {
    throw FunctionalError('WORKSPACE_EXPORT_INCOMPATIBLE_TYPE', { type: workspace.type });
  }
  const generatedManifest = await convertDashboardManifestIds(context, user, workspace.manifest, 'internal');
  const exportConfigration = {
    openCTI_version: pjson.version,
    type: 'dashboard',
    configuration: {
      name: workspace.name,
      manifest: generatedManifest,
    },
  };
  return JSON.stringify(exportConfigration);
};

export const generateWidgetExportConfiguration = async (context: AuthContext, user: AuthUser, workspace: BasicStoreEntityWorkspace, widgetId: string) => {
  if (workspace.type !== 'dashboard') {
    throw FunctionalError('WORKSPACE_EXPORT_INCOMPATIBLE_TYPE', { type: workspace.type });
  }
  const result = await exportDashboardWidget(context, user, workspace.manifest, widgetId);
  if (!result.success) {
    throw FunctionalError('WIDGET_EXPORT_NOT_FOUND', { workspace: workspace.id, widget: widgetId });
  }
  return result.data;
};
