import { v4 as uuid } from 'uuid';
import * as R from 'ramda';
import { useEffect, useMemo, useRef, useState } from 'react';
import fileDownload from 'js-file-download';
import type { Widget, WidgetLayout } from '../../utils/widget/widget';
import { deserializeDashboardManifestForFrontend, prepareManifest, serializeDashboardManifestForBackend } from './dashboard-utils';
import type { DashboardConfig, DashboardLike, DashboardManifest, DashboardWidget } from './dashboard-types';
import useDebounceCallback from '../../utils/hooks/useDebounceCallback';
import { applyDateChange, type DashboardDateField } from './dashboardTimeRange';

const LAYOUT_SAVE_DEBOUNCE_MS = 300;

interface SaveManifestOptions {
  layouts: Record<string, WidgetLayout>;
  noRefresh: boolean;
  onCompleted?: () => void;
  onError?: (error: Error) => void;
}

interface useDashboardProps {
  entity: DashboardLike | undefined | null;
  onSave?: (
    entityId: string,
    newSerializedManifest: string,
    noRefresh: boolean,
    onCompleted: () => void,
    onError?: (error: Error) => void,
  ) => void;
  onImportWidget?: (entityId: string, widgetConfigFile: File, serializedManifest: string) => void;
  onExportWidget?: (entityId: string, widget: { id: string; type: string }) => Promise<string | null>;
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
  const manifest = useMemo(
    () => deserializeDashboardManifestForFrontend(serializedManifest),
    [serializedManifest],
  );

  // Dashboard variables, refreshed when workspace is updated.
  const variables = useMemo(() => manifest.variables ?? [], [manifest]);

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

  const saveManifest = (
    newManifest: DashboardManifest,
    opts: SaveManifestOptions = { layouts: widgetsLayouts, noRefresh: false },
  ) => {
    const { layouts, noRefresh, onCompleted, onError } = opts;
    const preparedManifest = prepareManifest(newManifest, layouts);
    const newManifestEncoded = serializeDashboardManifestForBackend(preparedManifest);
    // Sometimes (in case of layout adjustment) we do not want to re-fetch
    // all the manifest because widgets data is still the same, and it's costly
    // in performance.
    if (serializedManifest !== newManifestEncoded) {
      const handleCompleted = () => {
        setDeleting(false);
        onCompleted?.();
      };
      // The error callback is only handed when someone waits for the result.
      if (onError) onSave?.(entity?.id ?? '', newManifestEncoded, noRefresh, handleCompleted, onError);
      else onSave?.(entity?.id ?? '', newManifestEncoded, noRefresh, handleCompleted);
    } else {
      onCompleted?.();
    }
  };

  const debouncedSaveLayout = useDebounceCallback(
    (currentManifest: DashboardManifest, layouts: Record<string, WidgetLayout>) => {
      saveManifest(currentManifest, { layouts, noRefresh: true });
    },
    LAYOUT_SAVE_DEBOUNCE_MS,
  );

  const cancelPendingLayoutSave = () => {
    debouncedSaveLayout.cancel();
  };

  const handleDateChange = (type: DashboardDateField, value: string | null) => {
    cancelPendingLayoutSave();
    saveManifest({ ...manifest, config: applyDateChange(manifest.config, type, value) });
  };

  // Saved with the current widget layouts: the manifest of the store misses the moves saved without refresh.
  // The config changes still being saved. The manifest only reflects a change once its save is done: a change made
  // meanwhile (another switch flipped) builds on it, or it would send the old value back and the server would keep that.
  const pendingConfig = useRef<{ count: number; patch: Partial<DashboardConfig> }>({ count: 0, patch: {} });
  const handleConfigChange = (patch: Partial<DashboardConfig>) => new Promise<void>((resolve, reject) => {
    cancelPendingLayoutSave();
    const pending = pendingConfig.current;
    pending.patch = { ...pending.patch, ...patch };
    pending.count += 1;
    const settle = () => {
      pending.count -= 1;
      if (pending.count === 0) pending.patch = {};
    };
    saveManifest(
      { ...manifest, config: { ...manifest.config, ...pending.patch } },
      {
        layouts: widgetsLayouts,
        noRefresh: false,
        onCompleted: () => {
          settle();
          resolve();
        },
        onError: (error) => {
          settle();
          reject(error);
        },
      },
    );
  });

  const getNextRow = () => {
    return widgetsArray.reduce((max, { layout }) => {
      const widgetEndRow = layout.y + layout.h;
      return widgetEndRow > max ? widgetEndRow : max;
    }, 0);
  };

  const handleImportWidget = (widgetConfigFile: File) => {
    cancelPendingLayoutSave();
    const preparedManifest = prepareManifest(manifest, widgetsLayouts);
    const manifestEncoded = serializeDashboardManifestForBackend(preparedManifest);
    onImportWidget?.(entity?.id ?? '', widgetConfigFile, manifestEncoded);
  };

  const handleExportWidget = (id: string, widget: { id: string; type: string }) => {
    if (!onExportWidget) {
      return;
    }
    onExportWidget(id, widget)
      .then((exportedWidget: string | null) => {
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

  const handleAddWidget = (widgetConfig: Widget) => {
    cancelPendingLayoutSave();
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

  const handleUpdateWidget = (widgetManifest: DashboardWidget) => {
    cancelPendingLayoutSave();
    const newManifest = {
      ...manifest,
      widgets: { ...manifest.widgets, [widgetManifest.id]: widgetManifest },
    };
    saveManifest(newManifest);
  };

  const handleDeleteWidget = (widgetId: string) => {
    cancelPendingLayoutSave();
    setDeleting(true);
    const newWidgets = { ...manifest.widgets };
    delete newWidgets[widgetId];
    saveManifest({
      ...manifest,
      widgets: newWidgets,
    });
  };

  const handleDuplicateWidget = (widgetToDuplicate: DashboardWidget) => {
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

    if (R.equals(newLayouts, widgetsLayouts)) return;

    setWidgetsLayouts(newLayouts);
    debouncedSaveLayout(manifest, newLayouts);
  };

  const config = manifest.config;

  return {
    handleAddWidget,
    handleDateChange,
    handleConfigChange,
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
    variables,
  };
}

export default useDashboard;
