import { v4 as uuid } from 'uuid';
import * as R from 'ramda';
import { useEffect, useMemo, useState } from 'react';
import fileDownload from 'js-file-download';
import type { Widget, WidgetLayout } from '../../utils/widget/widget';
import { deserializeDashboardManifestForFrontend, prepareManifest, serializeDashboardManifestForBackend } from './dashboard-utils';
import type { DashboardLike, DashboardManifest, DashboardWidget } from './dashboard-types';

interface useDashboardProps {
  entity: DashboardLike | undefined | null;
  onSave?: (entityId: string, newSerializedManifest: string, noRefresh: boolean, onCompleted: () => void) => void;
  onImportWidget?: (entityId: string, widgetConfigFile: File, serializedManifest: string) => void;
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
  const manifest = useMemo(
    () => deserializeDashboardManifestForFrontend(serializedManifest),
    [serializedManifest],
  );

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

  const saveManifest = (newManifest: DashboardManifest, opts = { layouts: widgetsLayouts, noRefresh: false }) => {
    const { layouts, noRefresh } = opts;
    const preparedManifest = prepareManifest(newManifest, layouts);
    const newManifestEncoded = serializeDashboardManifestForBackend(preparedManifest);
    // Sometimes (in case of layout adjustment) we do not want to re-fetch
    // all the manifest because widgets data is still the same, and it's costly
    // in performance.
    if (serializedManifest !== newManifestEncoded) {
      onSave?.(entity?.id ?? '', newManifestEncoded, noRefresh, () => {
        setDeleting(false);
      });
    }
  };

  const handleDateChange = (type: 'startDate' | 'endDate' | 'relativeDate', value: string | null) => {
    let newManifest = {
      ...manifest,
      config: {
        ...manifest.config,
        [type]: value === 'none' ? null : value,
      },
    } satisfies DashboardManifest;
    if (type === 'relativeDate' && value !== 'none') {
      newManifest = {
        ...newManifest,
        config: {
          ...newManifest.config,
          startDate: null,
          endDate: null,
        },
      } satisfies DashboardManifest;
    }
    saveManifest(newManifest);
  };

  const getNextRow = () => {
    return widgetsArray.reduce((max, { layout }) => {
      const widgetEndRow = layout.y + layout.h;
      return widgetEndRow > max ? widgetEndRow : max;
    }, 0);
  };

  const handleImportWidget = (widgetConfigFile: File) => {
    const preparedManifest = prepareManifest(manifest, widgetsLayouts);
    const manifestEncoded = serializeDashboardManifestForBackend(preparedManifest);
    onImportWidget?.(entity?.id ?? '', widgetConfigFile, manifestEncoded);
  };

  const handleExportWidget = (id: string, widget: { id: string; type: string }) => {
    if (!onExportWidget) {
      return;
    }
    onExportWidget(id, widget)
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

  const handleAddWidget = (widgetConfig: Widget) => {
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
