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
import { findSavedFilter } from '../savedFilter/savedFilter-domain';
import type { Widget, WidgetDataSelection } from '../../generated/graphql';

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

/**
 * Resolves a single saved filter reference within a data selection:
 * Replaces the saved filter id with the actual inline filters and removes the saved filter reference.
 */
const resolveSavedFilterReference = async (
  context: AuthContext,
  user: AuthUser,
  widgetDefinitionId: string,
  selection: WidgetDataSelection,
  savedFiltersIdKey: 'filters_id' | 'dynamicFrom_id' | 'dynamicTo_id',
  filtersKey: 'filters' | 'dynamicFrom' | 'dynamicTo',
) => {
  const savedFiltersId = selection[savedFiltersIdKey];
  if (savedFiltersId && isNotEmptyField(savedFiltersId)) {
    const savedFilter = await findSavedFilter(context, user, savedFiltersId);
    if (!savedFilter) {
      throw FunctionalError('Saved filter not found', { widget: widgetDefinitionId, savedFiltersId });
    }
    try {
      selection[filtersKey] = JSON.parse(savedFilter.filters);
      selection[savedFiltersIdKey] = undefined;
    } catch (error) {
      throw FunctionalError('Failed to parse saved filter', { error, widget: widgetDefinitionId, savedFiltersId, savedFiltersContent: savedFilter.filters });
    }
  }
};

/**
 * Resolves saved filter references in widget data selections:
 * Replaces saved filters ids with the actual inline filters and removes the saved filters references.
 */
export const resolveSavedFiltersInDataSelection = async (
  context: AuthContext,
  user: AuthUser,
  widgetDefinition: Widget,
) => {
  const dataSelection = widgetDefinition.dataSelection;
  if (dataSelection) {
    await Promise.all(dataSelection.map(async (selection: any) => {
      await Promise.all([
        resolveSavedFilterReference(context, user, widgetDefinition.id, selection, 'filters_id', 'filters'),
        resolveSavedFilterReference(context, user, widgetDefinition.id, selection, 'dynamicFrom_id', 'dynamicFrom'),
        resolveSavedFilterReference(context, user, widgetDefinition.id, selection, 'dynamicTo_id', 'dynamicTo'),
      ]);
    }));
  }
};

export const exportDashboardWidget = async (
  context: AuthContext,
  user: AuthUser,
  manifest: string,
  widgetId: string,
) => {
  const parsedManifest = fromB64(manifest ?? '{}');
  if (parsedManifest && isNotEmptyField(parsedManifest.widgets) && parsedManifest.widgets[widgetId]) {
    const widgetDefinition = parsedManifest.widgets[widgetId];
    await resolveSavedFiltersInDataSelection(context, user, widgetDefinition);
    await convertWidgetsIds(context, user, [widgetDefinition], 'internal');
    delete widgetDefinition.id; // Remove current widget id
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

/**
 * Convert dashboard widget ids between internal and STIX 2_1 formats.
 *
 * - Export (`from = 'internal'`): filter ids are converted to STIX ids and
 *   saved filter references are resolved to inline filter content.
 * - Import (`from = 'stix'`): filter ids are converted back to internal ids.
 */
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
    const widgetDefinitions: Widget[] = Object.values(widgets);
    if (from === 'internal') { // for exports: replace saved filters ids with the associated filters content
      await Promise.all(widgetDefinitions.map((widgetDefinition) => resolveSavedFiltersInDataSelection(context, user, widgetDefinition)));
    }
    await convertWidgetsIds(context, user, widgetDefinitions, from);
    return toB64(parsedManifest) as string;
  }
  return manifest;
};
