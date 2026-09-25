import { useCallback, useMemo } from 'react';
import useAuth from '../../hooks/useAuth';
import { resolveDrilldownLink } from './widgetDrilldown';
import type { DrilldownBucket, WidgetDateRange } from './widgetDrilldown-types';
import type { WidgetDataSelection, WidgetPerspective } from '../widget';

export interface WidgetDrilldown {
  getLink: (selectionIndex: number, bucket: DrilldownBucket) => string | null;
}

/**
 * The only React-aware piece of the drill-down: it supplies the filter keys
 * schema so the resolver itself stays pure.
 *
 * `range` and `interval` must be the ones the widget query actually used, not
 * values recomputed from the dashboard config — see `DrilldownInput.range`.
 *
 * `getLink` takes a selection index because multi-series widgets hold one data
 * selection per series and ApexCharts reports `seriesIndex` on click.
 */
const useWidgetDrilldown = ({
  perspective,
  resolvedDataSelection,
  range,
  interval,
}: {
  perspective: WidgetPerspective;
  resolvedDataSelection: WidgetDataSelection[];
  range: WidgetDateRange;
  interval?: string | null;
}): WidgetDrilldown => {
  const { filterKeysSchema } = useAuth().schema;

  const getLink = useCallback((selectionIndex: number, bucket: DrilldownBucket) => {
    const dataSelection = resolvedDataSelection[selectionIndex];
    if (!dataSelection) return null;
    return resolveDrilldownLink({ perspective, dataSelection, range, interval, bucket, filterKeysSchema });
  }, [perspective, resolvedDataSelection, range, interval, filterKeysSchema]);

  return useMemo(() => ({ getLink }), [getLink]);
};

export default useWidgetDrilldown;
