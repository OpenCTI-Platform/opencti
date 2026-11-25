import React, { useMemo, useState } from 'react';
import GraphToolbarTimeRange from '../../../../../components/graph/components/GraphToolbarTimeRange';
import { computeTimeRangeInterval, computeTimeRangeValues, countTimeRangeFilters, type GraphTimeRange } from '../../../../../components/graph/utils/graphTimeRange';
import { useFormatter } from '../../../../../components/i18n';
import type { ScoringLink } from './ttpAnalyser';
import { getMatrixFilterOptions, type InvestigationMatrixFilters, matrixFiltersInterval } from './matrixFilters';
import { useInvestigationMatrixFilterActions } from './useInvestigationMatrixFilterActions';

interface MatrixFilterControlsInput {
  links: ScoringLink[];
  filters: InvestigationMatrixFilters;
  onFiltersChange: (change: Partial<InvestigationMatrixFilters>) => void;
  onFiltersClear: () => void;
}

/**
 * The filters of the matrix toolbar: their actions, and the time range panel the toolbar draws under its row
 * while the time range is open.
 */
const useMatrixFilterControls = ({ links, filters, onFiltersChange, onFiltersClear }: MatrixFilterControlsInput) => {
  const { t_i18n } = useFormatter();
  const [timeRangeOpen, setTimeRangeOpen] = useState(false);
  const options = useMemo(() => getMatrixFilterOptions(links, t_i18n('None')), [links, t_i18n]);
  // Computed once for the panel and the badge: without any dated link, the range is set from now.
  const timeRange = useMemo<GraphTimeRange>(() => {
    const interval = computeTimeRangeInterval(options.datedLinks);
    return { interval, values: computeTimeRangeValues(interval, options.datedLinks) };
  }, [options]);

  const actions = useInvestigationMatrixFilterActions({
    options,
    timeRange,
    filters,
    onChange: onFiltersChange,
    onClear: onFiltersClear,
    timeRangeOpen,
    onToggleTimeRange: () => setTimeRangeOpen((open) => !open),
  });

  // The whole range is stored as no range at all, so that it neither counts as a filter nor needs clearing.
  // The slider snaps its ends to its 30-minute steps when it mounts and reports them: an end snapped off
  // the full range is still the whole range, and an unchanged range is not written again.
  const handleTimeRangeChange = (interval: [Date, Date]) => {
    const next: [string, string] | undefined = countTimeRangeFilters(timeRange.interval, interval) === 0
      ? undefined
      : [interval[0].toISOString(), interval[1].toISOString()];
    const current = filters.timeRange;
    if (next?.[0] === current?.[0] && next?.[1] === current?.[1]) return;
    onFiltersChange({ timeRange: next });
  };

  // Only mounted while shown, as in the graph: its handles would stay reachable from the keyboard.
  const timeRangePanel = timeRangeOpen ? (
    <GraphToolbarTimeRange
      timeRange={timeRange}
      selectedInterval={matrixFiltersInterval(filters)}
      onChange={handleTimeRangeChange}
    />
  ) : null;

  return { actions, timeRangeOpen, timeRangePanel };
};

export default useMatrixFilterControls;
