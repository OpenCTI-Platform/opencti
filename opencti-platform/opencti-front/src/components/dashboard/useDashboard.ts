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

// One write of the manifest, built when it is sent: from the last manifest sent, so that it keeps what the writes
// before it changed, with the current layouts.
interface ManifestWrite {
  update: (base: DashboardManifest) => DashboardManifest;
  noRefresh: boolean;
  onCompleted?: () => void;
  onError?: (error: Error) => void;
}

interface useDashboardProps {
  entity: DashboardLike | undefined | null;
  // Must call onCompleted or onError in every case: the next write waits for it.
  onSave?: (
    entityId: string,
    newSerializedManifest: string,
    noRefresh: boolean,
    onCompleted: () => void,
    onError: (error: Error) => void,
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

  // The writes are sent one at a time: each one carries the whole manifest, so two of them in flight would let the
  // last one to reach the server undo the other (a layout save sent while a config save is pending, for instance).
  const latest = useRef({ manifest, serializedManifest, layouts: widgetsLayouts });
  const writes = useRef<{ busy: boolean; waiting: ManifestWrite[]; lastSent: { manifest: DashboardManifest; encoded: string } | null }>({
    busy: false,
    waiting: [],
    lastSent: null,
  });
  useEffect(() => {
    latest.current.manifest = manifest;
    latest.current.serializedManifest = serializedManifest;
    // Once idle, the store is the reference again: it holds the last write, and any change made elsewhere.
    if (!writes.current.busy) writes.current.lastSent = null;
  }, [manifest, serializedManifest]);

  useEffect(() => {
    const layouts = widgetsArray.reduce((res, widget) => {
      res[widget.id] = widget.layout;
      return res;
    }, {} as Record<string, WidgetLayout>);
    setWidgetsLayouts(layouts);
    latest.current.layouts = layouts;
  }, [widgetsArray]);

  const sendNextWrite = () => {
    const queue = writes.current;
    const write = queue.waiting.shift();
    if (!write) {
      queue.busy = false;
      return;
    }
    queue.busy = true;
    const base = queue.lastSent?.manifest ?? latest.current.manifest;
    const baseEncoded = queue.lastSent?.encoded ?? latest.current.serializedManifest;
    const newManifest = prepareManifest(write.update(base), latest.current.layouts);
    const newManifestEncoded = serializeDashboardManifestForBackend(newManifest);
    if (!onSave || baseEncoded === newManifestEncoded) {
      write.onCompleted?.();
      sendNextWrite();
      return;
    }
    onSave(entity?.id ?? '', newManifestEncoded, write.noRefresh, () => {
      queue.lastSent = { manifest: newManifest, encoded: newManifestEncoded };
      setDeleting(false);
      write.onCompleted?.();
      sendNextWrite();
    }, (error) => {
      // Not saved: the next write builds on what the server has, not on this one.
      setDeleting(false);
      write.onError?.(error);
      sendNextWrite();
    });
  };

  const saveManifest = (write: ManifestWrite) => {
    writes.current.waiting.push(write);
    if (!writes.current.busy) sendNextWrite();
  };

  // Sometimes (in case of layout adjustment) we do not want to re-fetch
  // all the manifest because widgets data is still the same, and it's costly
  // in performance.
  const debouncedSaveLayout = useDebounceCallback(
    () => saveManifest({ update: (base) => base, noRefresh: true }),
    LAYOUT_SAVE_DEBOUNCE_MS,
  );

  // Any other write carries the current layouts.
  const cancelPendingLayoutSave = () => {
    debouncedSaveLayout.cancel();
  };

  const handleDateChange = (type: DashboardDateField, value: string | null) => {
    cancelPendingLayoutSave();
    saveManifest({ update: (base) => ({ ...base, config: applyDateChange(base.config, type, value) }), noRefresh: false });
  };

  const handleConfigChange = (patch: Partial<DashboardConfig>) => new Promise<void>((resolve, reject) => {
    cancelPendingLayoutSave();
    saveManifest({
      update: (base) => ({ ...base, config: { ...base.config, ...patch } }),
      noRefresh: false,
      onCompleted: resolve,
      onError: reject,
    });
  });

  const getNextRow = (widgets: DashboardManifest['widgets']) => {
    return Object.values(widgets).reduce((max, { layout }) => {
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
      update: (base) => ({
        ...base,
        widgets: {
          ...base.widgets,
          [widgetConfig.id]: {
            ...widgetConfig,
            layout: {
              i: widgetConfig.id,
              x: 0,
              y: getNextRow(base.widgets),
              w: 4,
              h: 2,
              moved: false,
              static: false,
            },
          },
        },
      }),
      noRefresh: false,
    });
  };

  const handleUpdateWidget = (widgetManifest: DashboardWidget) => {
    cancelPendingLayoutSave();
    saveManifest({
      update: (base) => ({ ...base, widgets: { ...base.widgets, [widgetManifest.id]: widgetManifest } }),
      noRefresh: false,
    });
  };

  const handleDeleteWidget = (widgetId: string) => {
    cancelPendingLayoutSave();
    setDeleting(true);
    saveManifest({
      update: (base) => {
        const newWidgets = { ...base.widgets };
        delete newWidgets[widgetId];
        return { ...base, widgets: newWidgets };
      },
      noRefresh: false,
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
    latest.current.layouts = newLayouts;
    debouncedSaveLayout();
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
