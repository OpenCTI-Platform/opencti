import { useEffect, useMemo, useRef, useState } from 'react';
import useAuth from '../../../utils/hooks/useAuth';
import { useFormatter } from '../../../components/i18n';
import type { Widget, WidgetHost, WidgetParameters } from '../../../utils/widget/widget';
import type { FilterGroup } from '../../../utils/filters/filtersHelpers-types';
import { type BreakdownResolution, getBreakdownEditorState, getWidgetBreakdownState, NO_BREAKDOWN_STATE, type WidgetBreakdownState } from '../../../utils/widget/widgetBreakdown';
import { fetchSavedFilterContent } from '../../../components/dashboard/dashboardVizUtils';
import { useOptionalDashboardVariableDefinitions } from '../../../components/dashboard/DashboardVariablesContext';

type EditedWidget = Pick<Widget, 'type' | 'perspective' | 'dataSelection'> & { parameters?: WidgetParameters | null };

/**
 * Breakdown of the edited widget (getWidgetBreakdownState), derived by the editor provider for all its steps:
 * the saved filter of the dataset is read once per opening, whatever the widget becomes meanwhile.
 * While the editor is not `open`, no breakdown is shown, nor kept or dropped.
 */
const useResolvedWidgetBreakdown = (widget: EditedWidget, host: WidgetHost, open: boolean): WidgetBreakdownState => {
  const { schema: { filterKeysSchema } } = useAuth();
  const { t_i18n } = useFormatter();
  const variables = useOptionalDashboardVariableDefinitions();
  const savedFilterId = widget.dataSelection[0]?.filters_id;
  const isSavedFilterNeeded = open && !!savedFilterId && getBreakdownEditorState(widget, host) !== 'hidden';
  const [savedFilter, setSavedFilter] = useState<{ id: string; filters: FilterGroup | null }>();
  // The saved filter being read: still read when the widget no longer needs it, to not read it again if it does
  const readingId = useRef<string>(undefined);
  const isSavedFilterRead = !!savedFilterId && savedFilter?.id === savedFilterId;
  // Read again each time the editor opens: the saved filter may have changed in between
  useEffect(() => {
    if (!open) {
      readingId.current = undefined;
      setSavedFilter(undefined);
    }
  }, [open]);
  useEffect(() => {
    if (!isSavedFilterNeeded || !savedFilterId || isSavedFilterRead || readingId.current === savedFilterId) {
      return;
    }
    readingId.current = savedFilterId;
    fetchSavedFilterContent(savedFilterId).then((filters) => {
      // Not kept for another saved filter, or once the editor is closed
      if (readingId.current === savedFilterId) {
        readingId.current = undefined;
        setSavedFilter({ id: savedFilterId, filters });
      }
    });
  }, [isSavedFilterNeeded, savedFilterId, isSavedFilterRead]);
  return useMemo(() => {
    if (!open) {
      return NO_BREAKDOWN_STATE;
    }
    let resolution: BreakdownResolution = 'resolved';
    if (savedFilterId) {
      // A saved filter that cannot be read, or holds no filters, leaves the types of the dataset unknown
      if (!isSavedFilterRead) {
        resolution = 'loading';
      } else if (!savedFilter?.filters) {
        resolution = 'failed';
      }
    }
    return getWidgetBreakdownState({
      filterKeysSchema,
      widget,
      host,
      savedFilter: { resolution, filters: isSavedFilterRead ? savedFilter?.filters : undefined },
      variables,
      translate: t_i18n,
    });
  }, [open, filterKeysSchema, widget, host, savedFilterId, isSavedFilterRead, savedFilter, variables, t_i18n]);
};

export default useResolvedWidgetBreakdown;
