import { useMemo } from 'react';
import { fromB64 } from '../../../utils/String';
import { deserializeDashboardManifestForFrontend } from '../../../utils/filters/filtersUtils';
import type { WidgetLayout } from '../../../utils/widget/widget';

/**
 * Display widgets in a layout.
 * Not to be used when editing the layout or widgets.
 *
 * @param serializedManifest - The serialized version of the widgets+layout content.
 */
function useDashboard(serializedManifest: string) {
  const manifest = useMemo(() =>
    deserializeDashboardManifestForFrontend(fromB64(serializedManifest)),
  [serializedManifest]);

  const widgetsArray = Object.values(manifest.widgets).filter(({ layout }) => layout);

  const widgetsLayouts = widgetsArray.reduce((res, widget) => {
    res[widget.id] = widget.layout!;
    return res;
  }, {} as Record<string, WidgetLayout>);

  const config = manifest.config;

  return {
    widgetsArray,
    widgetsLayouts,
    config,
  };
}

export default useDashboard;
