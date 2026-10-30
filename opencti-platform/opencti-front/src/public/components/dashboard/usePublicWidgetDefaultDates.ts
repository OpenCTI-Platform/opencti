import { useMemo, useState } from 'react';
import { monthsAgo, now } from '../../../utils/Time';

/**
 * Resolves the date range for a public dashboard widget, falling back to the
 * default 12-month window when the widget has no configured dates. A widget
 * can give its own default start date, computed once per mount.
 *
 * The defaults are memoized once per mount so unrelated re-renders (e.g. a
 * manual/auto refresh) don't produce fresh now()/monthsAgo() timestamps, which
 * would defeat the variables-equality guard in usePublicDashboardViz and
 * relaunch the widget query on every render.
 */
const usePublicWidgetDefaultDates = (
  startDate?: string | null,
  endDate?: string | null,
  getDefaultStartDate: () => string = () => monthsAgo(12),
) => {
  const [defaultStartDate] = useState(getDefaultStartDate);
  const defaultEndDate = useMemo(() => now(), []);
  return {
    startDate: startDate ?? defaultStartDate,
    endDate: endDate ?? defaultEndDate,
  };
};

export default usePublicWidgetDefaultDates;
