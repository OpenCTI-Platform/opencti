import { v4 as uuidv4 } from 'uuid';
import type { FileHandle } from 'fs/promises';
import pjson from '../../../package.json';
import type { AuthContext, AuthUser } from '../../types/user';
import { fromB64, toB64 } from '../../utils/base64';
import { isNotEmptyField } from '../../database/utils';
import { FunctionalError } from '../../config/errors';
import { extractContentFrom } from '../../utils/fileToContent';
import { convertWidgetsIds } from '../workspace/workspace-utils';
import { isCompatibleVersionWithMinimal } from '../../utils/version';
import type { ConfigImportData, WidgetConfigImportData, WidgetConfiguration } from './dashboard-types';

const MINIMAL_COMPATIBLE_VERSION = '5.12.16';

const configurationImportTypeValidation = {
  dashboard: 'Invalid type. Please import OpenCTI dashboard-type only',
  widget: 'Invalid type. Please import OpenCTI widget-type only',
} as const;

export const checkDashboardConfigurationImport = (type: string, parsedData: ConfigImportData) => {
  if (type in configurationImportTypeValidation && parsedData.type !== type) {
    throw FunctionalError(configurationImportTypeValidation[type as keyof typeof configurationImportTypeValidation], {
      reason: parsedData.type,
    });
  }

  if (!isCompatibleVersionWithMinimal(parsedData.openCTI_version, MINIMAL_COMPATIBLE_VERSION)) {
    throw FunctionalError(
      `Invalid version of the platform. Please upgrade your OpenCTI. Minimal version required: ${MINIMAL_COMPATIBLE_VERSION}`,
      { reason: parsedData.openCTI_version },
    );
  }
};

export const exportDashboardWidget = async (context: AuthContext, user: AuthUser, manifest: string, widgetId: string) => {
  const parsedManifest = fromB64(manifest ?? '{}');
  if (parsedManifest && isNotEmptyField(parsedManifest.widgets) && parsedManifest.widgets[widgetId]) {
    const widgetDefinition = parsedManifest.widgets[widgetId];
    delete widgetDefinition.id; // Remove current widget id
    await convertWidgetsIds(context, user, [widgetDefinition], 'internal');
    const exportConfigration = {
      openCTI_version: pjson.version,
      type: 'widget',
      configuration: toB64(widgetDefinition) as string,
    };
    return { success: true, data: JSON.stringify(exportConfigration) } as const;
  }
  return { success: false } as const;
};

export const importDashboardWidgetConfiguration = async (
  context: AuthContext,
  user: AuthUser,
  file: Promise<FileHandle>,
  manifest: string | null | undefined,
) => {
  const parsedData = await extractContentFrom<WidgetConfigImportData>(file);
  checkDashboardConfigurationImport('widget', parsedData);
  const widgetDefinition = fromB64(parsedData.configuration);
  await convertWidgetsIds(context, user, [widgetDefinition], 'stix');
  const importedWidgetId = uuidv4();
  const dashboardManifestObjects = fromB64(manifest ?? undefined);

  // When importing a widget, change its position to not break
  // the current layout of the dashboard.
  // It is moved on a new line.
  const widgetsArray = Object.values(dashboardManifestObjects.widgets ?? [])
    .map((widget) => widget) as WidgetConfiguration[];
  const nextRow = widgetsArray.reduce((max, { layout }) => {
    const widgetEndRow = layout.y + layout.h;
    return widgetEndRow > max ? widgetEndRow : max;
  }, 0);

  const updatedObjects = {
    ...dashboardManifestObjects,
    widgets: {
      ...dashboardManifestObjects.widgets,
      [importedWidgetId]: {
        id: importedWidgetId,
        ...widgetDefinition,
        layout: {
          ...widgetDefinition.layout,
          x: 0,
          y: nextRow,
        },
      },
    },
  };
  const updatedManifest = toB64(updatedObjects);
  return {
    updatedManifest,
    importedWidgetId,
  };
};

// region workspace ids converter_2_1
// Export => Dashboard filter ids must be converted to standard id
// Import => Dashboards filter ids must be converted back to internal id
export const convertDashboardManifestIds = async (
  context: AuthContext,
  user: AuthUser,
  manifest: string,
  from: 'internal' | 'stix',
): Promise<string> => {
  const parsedManifest = fromB64(manifest ?? '{}');
  // Regeneration for dashboards
  if (parsedManifest && isNotEmptyField(parsedManifest.widgets)) {
    const { widgets } = parsedManifest;
    const widgetDefinitions = Object.values(widgets);
    await convertWidgetsIds(context, user, widgetDefinitions, from);
    return toB64(parsedManifest) as string;
  }
  return manifest;
};
// endregion
