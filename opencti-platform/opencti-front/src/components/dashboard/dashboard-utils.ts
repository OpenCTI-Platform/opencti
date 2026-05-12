import type { GqlWidgetDataSelection, WidgetLayout } from '../../utils/widget/widget';
import { fromB64, toB64 } from '../../utils/String';
import { sanitizeFilterGroupKeysForBackend, sanitizeFilterGroupKeysForFrontend } from '../../utils/filters/filtersUtils';
import type { DashboardManifest, DashboardWidget } from './dashboard-types';

/**
 * Serialize a complex dashboard manifest, sanitizing all filters inside the manifest before.
 * @param manifest
 */
export const serializeDashboardManifestForBackend = (
  manifest: DashboardManifest,
): string => {
  const newWidgets: Record<string, unknown> = {};
  const widgetIds = manifest.widgets ? Object.keys(manifest.widgets) : [];
  widgetIds.forEach((id) => {
    const widget = manifest.widgets[id];
    newWidgets[id] = {
      ...widget,
      dataSelection: widget.dataSelection.map(
        (selection) => ({
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

  return toB64(JSON.stringify({
    ...manifest,
    widgets: newWidgets,
  }));
};

export const deserializeDashboardManifestForFrontend = (
  manifestB64Str: string | undefined | null,
): DashboardManifest => {
  const widgets: Record<string, DashboardWidget> = {};
  if (!manifestB64Str) {
    return {
      widgets,
      config: {},
    };
  }
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
        // Assert backend
        (selection: GqlWidgetDataSelection) => ({
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
 * Merge a manifest with local layout changes.
 *
 * @remarks
 * We need to sync manifest with local layouts before sending for update.
 * A desync occurs when resizing or moving a widget because in those cases
 * we skip a complete reload to avoid performance issue.
 *
 * @param newManifest Manifest to merge with local changes.
 * @param layouts Local layout changes.
 */
export const prepareManifest = (newManifest: DashboardManifest, layouts: Record<string, WidgetLayout>) => {
  const syncWidgets = Object.values(newManifest.widgets).reduce((res, widget) => {
    const localLayout = layouts[widget.id];
    res[widget.id] = {
      ...widget,
      layout: localLayout || widget.layout,
    };
    return res;
  }, {} as DashboardManifest['widgets']);
  return {
    ...newManifest,
    widgets: syncWidgets,
  };
};
