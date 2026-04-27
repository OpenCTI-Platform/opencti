import type { WidgetLayout } from '../../utils/widget/widget';
import { fromB64, toB64 } from '../../utils/String';
import { sanitizeFilterGroupKeysForBackend, sanitizeFilterGroupKeysForFrontend } from '../../utils/filters/filtersUtils';
import type { DashboardManifest } from './dashboard-types';

// Dashboard manifests are complex objects with filters deeply nested in widgets configurations
// (de)serialization is a bit more complex
// We use any here and use it when manipulating the manifest or internal fields
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type AnyForDashboardManifest = any;

/**
 * Serialize a complex dashboard manifest, sanitizing all filters inside the manifest before.
 * @param manifest
 */
export const serializeDashboardManifestForBackend = (
  manifest: AnyForDashboardManifest,
): string => {
  const newWidgets: Record<string, AnyForDashboardManifest> = {};
  const widgetIds = manifest.widgets ? Object.keys(manifest.widgets) : [];
  widgetIds.forEach((id) => {
    const widget = manifest.widgets[id];
    newWidgets[id] = {
      ...widget,
      dataSelection: widget.dataSelection.map(
        (selection: AnyForDashboardManifest) => ({
          ...selection,
          filters: selection.filters
            ? sanitizeFilterGroupKeysForBackend(selection.filters)
            : undefined,
          dynamicFrom: selection.dynamicFrom
            ? sanitizeFilterGroupKeysForBackend(selection.dynamicFrom)
            : undefined,
          dynamicTo: selection.dynamicTo
            ? sanitizeFilterGroupKeysForBackend(selection.dynamicTo)
            : undefined,
        }),
      ),
    };
  });

  return JSON.stringify({
    ...manifest,
    widgets: newWidgets,
  });
};

export const deserializeDashboardManifestForFrontend = (
  manifestB64Str: string,
): DashboardManifest => {
  const widgets: Record<string, AnyForDashboardManifest> = {};
  const manifestStr = fromB64(manifestB64Str);
  if (!manifestStr) {
    return {
      widgets,
      config: {},
    };
  }
  const manifest = JSON.parse(manifestStr);
  const widgetIds = manifest.widgets ? Object.keys(manifest.widgets) : [];
  widgetIds.forEach((id) => {
    const widget = manifest.widgets[id];
    widgets[id] = {
      ...widget,
      dataSelection: widget.dataSelection.map(
        (selection: AnyForDashboardManifest) => ({
          ...selection,
          filters: selection.filters
            ? sanitizeFilterGroupKeysForFrontend(selection.filters)
            : undefined,
          dynamicFrom: selection.dynamicFrom
            ? sanitizeFilterGroupKeysForFrontend(selection.dynamicFrom)
            : undefined,
          dynamicTo: selection.dynamicTo
            ? sanitizeFilterGroupKeysForFrontend(selection.dynamicTo)
            : undefined,
        }),
      ),
    };
  });

  return {
    config: {},
    ...manifest,
    widgets,
  };
};

/**
 * Merge a manifest with some layouts and transform it in base64.
 *
 * @param newManifest Manifest to merge with local changes and stringify.
 * @param layouts Local layout changes.
 * @returns Manifest in B64.
 */
export const prepareManifest = (newManifest: DashboardManifest, layouts: Record<string, WidgetLayout>) => {
  // Need to sync manifest with local layouts before sending for update.
  // A desync occurs when resizing or moving a widget because in those cases
  // we skip a complete reload to avoid performance issue.
  const syncWidgets = Object.values(newManifest.widgets).reduce((res, widget) => {
    const localLayout = layouts[widget.id];
    res[widget.id] = {
      ...widget,
      layout: localLayout || widget.layout,
    };
    return res;
  }, {} as DashboardManifest['widgets']);
  const manifestToSave = {
    ...newManifest,
    widgets: syncWidgets,
  };

  const strManifest = serializeDashboardManifestForBackend(manifestToSave);
  return toB64(strManifest);
};
