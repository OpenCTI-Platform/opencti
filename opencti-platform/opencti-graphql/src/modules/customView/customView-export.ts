import { GraphQLError } from 'graphql';
import { logApp } from '../../config/conf';
import { FUNCTIONAL_ERROR } from '../../config/errors';
import type { AuthContext, AuthUser } from '../../types/user';
import { convertDashboardManifestIds } from '../dashboard/dashboard-utils';
import { stripServerOwnedManifestKeys } from '../workspace/workspace-variables-utils';
import type { BasicStoreEntityCustomView } from './customView-types';

// The manifest of a bundle: the ids are standard ids, the variables and the presets are left out (a custom view never keeps them).
// A saved filter that does not exist keeps its reference: the widget shows it as missing, as on this platform.
// Saved filters that exist are inlined, as the file export and the export of the dashboards do: an overwrite on the platform the bundle comes from
// therefore replaces a saved filter reference by its filters, as it does for a dashboard.
// A manifest the platform cannot read (a widget without data selection, a value that is not base64 json) is exported as stored, with a warning:
// it must not fail the export of every other item of the bundle. The import refuses it with a reason. A failure of the platform itself is not
// swallowed.
const toBundleManifest = async (context: AuthContext, user: AuthUser, customView: BasicStoreEntityCustomView, encoded: string) => {
  try {
    return await convertDashboardManifestIds(context, user, stripServerOwnedManifestKeys(encoded), 'internal', { keepMissingSavedFilters: true });
  } catch (cause) {
    if (cause instanceof GraphQLError && cause.extensions.code !== FUNCTIONAL_ERROR) {
      throw cause;
    }
    logApp.warn('[CONFIG PRESET] The manifest of a custom view cannot be converted for the export, it is exported as stored', { cause, custom_view_id: customView.id });
    return encoded;
  }
};

// A custom view in the import format (customView-import-schema). Only what the view is: whether it is enabled or the default of its entity type
// is a choice of the platform that imports it, and the file export of a custom view does not carry it either.
export const exportCustomViewToBundle = async (context: AuthContext, user: AuthUser, customView: BasicStoreEntityCustomView) => {
  const manifest = customView.manifest ? await toBundleManifest(context, user, customView, customView.manifest) : undefined;
  return {
    name: customView.name,
    target_entity_type: customView.target_entity_type,
    // Always written, empty or not: an overwrite then makes the description of the view the one of the bundle, an empty one included
    description: customView.description ?? '',
    ...(manifest ? { manifest } : {}),
  };
};
