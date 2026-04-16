import { v4 as uuid } from 'uuid';
import * as R from 'ramda';
import { useEffect, useMemo, useState } from 'react';
import fileDownload from 'js-file-download';
import { fromB64, toB64 } from '../../utils/String';
import { deserializeDashboardManifestForFrontend, serializeDashboardManifestForBackend } from '../../utils/filters/filtersUtils';
import type { WidgetLayout } from '../../utils/widget/widget';
import type { DashboardLike, DashboardManifest } from './dashboard-types';

interface useDashboardProps {
  entity: DashboardLike | undefined | null;
  onSave?: (entityId: string, newSerializedManifest: string, noRefresh: boolean, onCompleted: () => void) => void;
  onImportWidget?: (entityId: string, widgetConfig: unknown, serializedManifest: string) => void;
  onExportWidget?: (entityId: string, widget: { id: string; type: string }) => Promise<string>;
}

function useDashboard({
  entity,
  onImportWidget,
  onExportWidget,
  onSave,
}: useDashboardProps) {
  const serializedManifest = entity?.manifest;
  const [deleting, setDeleting] = useState(false);
  const [idToResize, setIdToResize] = useState<string | null>(null);
  const handleResize = (updatedWidgetId: string | null) => setIdToResize(updatedWidgetId);

  useEffect(() => {
    const timeout = setTimeout(() => {
      window.dispatchEvent(new Event('resize'));
    }, 1200);
    return () => {
      clearTimeout(timeout);
    };
  }, []);

  // Deserialized manifest, refreshed when workspace is updated.
  const manifest = useMemo(() => {
    return serializedManifest && serializedManifest.length > 0
      ? deserializeDashboardManifestForFrontend(fromB64(serializedManifest))
      : { widgets: {}, config: {} };
  }, [serializedManifest]);

  // Array of all widgets, refreshed when workspace is updated.
  const widgetsArray = useMemo(() => Object.values(manifest.widgets), [manifest]);

  // Map of widget layouts, refreshed when workspace is updated (thanks to useMemo below).
  // We use a local map of layouts to avoid a lot of computation when only changing position
  // or dimension of widgets.
  const [widgetsLayouts, setWidgetsLayouts] = useState<Record<string, WidgetLayout>>({});

  useEffect(() => {
    setWidgetsLayouts(
      widgetsArray.reduce((res, widget) => {
        res[widget.id] = widget.layout;
        return res;
      }, {} as Record<string, WidgetLayout>),
    );
  }, [widgetsArray]);

  /**
   * Merge a manifest with some layouts and transform it in base64.
   *
   * @param newManifest Manifest to merge with local changes and stringify.
   * @param layouts Local layout changes.
   * @returns Manifest in B64.
   */
  const prepareManifest = (newManifest: DashboardManifest, layouts: Record<string, WidgetLayout>) => {
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

  const saveManifest = (newManifest: DashboardManifest, opts = { layouts: widgetsLayouts, noRefresh: false }) => {
    const { layouts, noRefresh } = opts;
    const newManifestEncoded = prepareManifest(newManifest, layouts);
    // Sometimes (in case of layout adjustment) we do not want to re-fetch
    // all the manifest because widgets data is still the same, and it's costly
    // in performance.
    if (serializedManifest !== newManifestEncoded) {
      onSave?.(entity?.id ?? '', newManifestEncoded, noRefresh, () => {
        setDeleting(false);
      });
    }
  };

  const handleDateChange = (type: string, value: unknown) => {
    let newManifest = {
      ...manifest,
      config: {
        ...manifest.config,
        [type]: value === 'none' ? null : value,
      },
    };
    if (type === 'relativeDate' && value !== 'none') {
      newManifest = {
        ...newManifest,
        config: {
          ...newManifest.config,
          startDate: null,
          endDate: null,
        },
      };
    }
    saveManifest(newManifest);
  };

  const getNextRow = () => {
    return widgetsArray.reduce((max, { layout }) => {
      const widgetEndRow = layout.y + layout.h;
      return widgetEndRow > max ? widgetEndRow : max;
    }, 0);
  };

  const handleImportWidget = (widgetConfig: unknown) => {
    const manifestEncoded = prepareManifest(manifest, widgetsLayouts);
    onImportWidget?.(entity?.id ?? '', widgetConfig, manifestEncoded);
  };

  const handleExportWidget = async (id: string, widget: { id: string; type: string }) => {
    onExportWidget?.(id, widget)
      .then((exportedWidget: string) => {
        if (!exportedWidget) {
          return;
        }
        const blob = new Blob([exportedWidget], {
          type: 'text/json',
        });
        const [day, month, year] = new Date()
          .toLocaleDateString('fr-FR')
          .split('/');
        const fileName = `${year}${month}${day}_octi_widget_${widget.type}.json`;
        fileDownload(blob, fileName);
      });
  };

  const handleAddWidget = (widgetConfig: DashboardManifest['widgets'][number]) => {
    saveManifest({
      ...manifest,
      widgets: {
        ...manifest.widgets,
        [widgetConfig.id]: {
          ...widgetConfig,
          layout: {
            i: widgetConfig.id,
            x: 0,
            y: getNextRow(),
            w: 4,
            h: 2,
            moved: false,
            static: false,
          },
        },
      },
    });
  };

  const handleUpdateWidget = (widgetManifest: DashboardManifest['widgets'][number]) => {
    const newManifest = {
      ...manifest,
      widgets: { ...manifest.widgets, [widgetManifest.id]: widgetManifest },
    };
    saveManifest(newManifest);
  };

  const handleDeleteWidget = (widgetId: string) => {
    setDeleting(true);
    const newWidgets = { ...manifest.widgets };
    delete newWidgets[widgetId];
    saveManifest({
      ...manifest,
      widgets: newWidgets,
    });
  };

  const handleDuplicateWidget = (widgetToDuplicate: DashboardManifest['widgets'][number]) => {
    handleAddWidget({
      ...widgetToDuplicate,
      id: uuid(),
    });
  };

  const handleLayoutChange = (layouts: ReadonlyArray<WidgetLayout>) => {
    if (deleting) return;

    const newLayouts = layouts.reduce((res, layout) => {
      res[layout.i] = layout;
      return res;
    }, {} as Record<string, WidgetLayout>);

    if (R.equals(newLayouts, widgetsLayouts)) return; // ⛔ prevent loop

    setWidgetsLayouts(newLayouts);
    saveManifest(manifest, { layouts: newLayouts, noRefresh: true });
  };

  const config = manifest.config;

  return {
    handleAddWidget,
    handleDateChange,
    handleUpdateWidget,
    handleDeleteWidget,
    handleDuplicateWidget,
    handleLayoutChange,
    handleImportWidget,
    handleExportWidget,
    idToResize,
    handleResize,
    config,
    widgetsArray,
    widgetsLayouts,
  };
}

export default useDashboard;
