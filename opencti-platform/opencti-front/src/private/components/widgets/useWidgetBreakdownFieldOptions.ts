import { useEffect, useMemo, useState } from 'react';
import useAuth from '../../../utils/hooks/useAuth';
import type { Widget } from '../../../utils/widget/widget';
import type { FilterGroup } from '../../../utils/filters/filtersHelpers-types';
import { getWidgetBreakdownFieldOptions } from '../../../utils/widget/widgetBreakdown';
import { fetchSavedFilterContent } from '../../../components/dashboard/dashboardVizUtils';
import { useOptionalDashboardVariableDefinitions } from '../../../components/dashboard/DashboardVariablesContext';

/**
 * Fields the edited widget can be broken down by, on the dataset its query reads: the content of its saved
 * filter, and the types its type variables allow, whatever their value. `isResolved` is false while the saved
 * filter is read, or when it cannot be: only the fields of any dataset are then offered.
 */
const useWidgetBreakdownFieldOptions = (widget: Pick<Widget, 'perspective' | 'dataSelection'>, enabled: boolean) => {
  const { schema: { filterKeysSchema } } = useAuth();
  const variables = useOptionalDashboardVariableDefinitions();
  const { perspective, dataSelection } = widget;
  const savedFilterId = dataSelection[0]?.filters_id;
  const [savedFilter, setSavedFilter] = useState<{ id: string; filters: FilterGroup | null }>();
  useEffect(() => {
    if (!enabled || !savedFilterId) {
      return undefined;
    }
    let cancelled = false;
    fetchSavedFilterContent(savedFilterId).then((filters) => {
      if (!cancelled) {
        setSavedFilter({ id: savedFilterId, filters });
      }
    });
    return () => {
      cancelled = true;
    };
  }, [enabled, savedFilterId]);
  const savedFilters = savedFilterId && savedFilter?.id === savedFilterId ? savedFilter.filters : null;
  const isResolved = !savedFilterId || !!savedFilters;
  const fieldOptions = useMemo(() => {
    if (!enabled) {
      return [];
    }
    const [firstSelection, ...otherSelections] = dataSelection;
    const resolvedSelection = savedFilters ? [{ ...firstSelection, filters: savedFilters }, ...otherSelections] : dataSelection;
    return getWidgetBreakdownFieldOptions(filterKeysSchema, { perspective, dataSelection: resolvedSelection }, variables);
  }, [enabled, filterKeysSchema, perspective, dataSelection, savedFilters, variables]);
  return { fieldOptions, isResolved };
};

export default useWidgetBreakdownFieldOptions;
