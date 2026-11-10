import { useEffect, useMemo, useRef, useState } from 'react';
import useAuth from '../../../utils/hooks/useAuth';
import { useFormatter } from '../../../components/i18n';
import type { Widget, WidgetHost, WidgetParameters } from '../../../utils/widget/widget';
import type { FilterGroup } from '../../../utils/filters/filtersHelpers-types';
import {
  type BreakdownResolution,
  getBreakdownEditorState,
  getBreakdownFieldsRequest,
  getWidgetBreakdownState,
  NO_BREAKDOWN_STATE,
  type WidgetBreakdownState,
} from '../../../utils/widget/widgetBreakdown';
import { fetchSavedFilterContent, fetchTimeSeriesBreakdownFields } from '../../../components/dashboard/dashboardVizUtils';
import { useOptionalDashboardVariableDefinitions } from '../../../components/dashboard/DashboardVariablesContext';

type EditedWidget = Pick<Widget, 'type' | 'perspective' | 'dataSelection'> & { parameters?: WidgetParameters | null };

// The keys of the fields read for each request, null for a request that failed
type BreakdownFields = ReadonlyMap<string, string[] | null>;
const NO_FIELDS: BreakdownFields = new Map();

/**
 * Breakdown of the edited widget (getWidgetBreakdownState), derived by the editor provider for all its steps:
 * the saved filter of the dataset is read once per opening, whatever the widget becomes meanwhile, and then the
 * fields the API offers for the dataset, once per opening for each perspective and types it reads.
 * Without `enabled` (the feature off, or the editor closed), no breakdown is shown, nor kept or dropped.
 */
const useResolvedWidgetBreakdown = (widget: EditedWidget, host: WidgetHost, enabled: boolean): WidgetBreakdownState => {
  const { schema: { filterKeysSchema } } = useAuth();
  const { t_i18n } = useFormatter();
  const variables = useOptionalDashboardVariableDefinitions();
  const savedFilterId = widget.dataSelection[0]?.filters_id;
  const isSavedFilterNeeded = enabled && !!savedFilterId && getBreakdownEditorState(widget, host) !== 'hidden';
  const [savedFilter, setSavedFilter] = useState<{ id: string; filters: FilterGroup | null }>();
  // The saved filter being read: still read when the widget no longer needs it, to not read it again if it does
  const readingId = useRef<string>(undefined);
  const isSavedFilterRead = !!savedFilterId && savedFilter?.id === savedFilterId;
  const [fields, setFields] = useState<BreakdownFields>(NO_FIELDS);
  // The requests of the fields being read, kept the same way
  const readingFields = useRef(new Set<string>());
  // Counts the openings of the editor: the fields read for a previous one are not kept
  const opening = useRef(0);
  // Read again each time the editor opens: the saved filter, or the fields, may have changed in between
  useEffect(() => {
    if (!enabled) {
      readingId.current = undefined;
      setSavedFilter(undefined);
      opening.current += 1;
      readingFields.current.clear();
      setFields(NO_FIELDS);
    }
  }, [enabled]);
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

  const savedFilterContent = useMemo(() => {
    // A saved filter that cannot be read, or holds no filters, leaves the types of the dataset unknown
    let resolution: BreakdownResolution = 'resolved';
    if (savedFilterId) {
      if (!isSavedFilterRead) {
        resolution = 'loading';
      } else if (!savedFilter?.filters) {
        resolution = 'failed';
      }
    }
    return { resolution, filters: isSavedFilterRead ? savedFilter?.filters : undefined };
  }, [savedFilterId, isSavedFilterRead, savedFilter]);
  // The fields of the dataset, asked once it is known
  const fieldsRequest = useMemo(
    () => (enabled ? getBreakdownFieldsRequest({ widget, host, savedFilter: savedFilterContent, variables }) : null),
    [enabled, widget, host, savedFilterContent, variables],
  );
  const fieldsKey = fieldsRequest ? JSON.stringify(fieldsRequest) : null;
  useEffect(() => {
    if (!fieldsRequest || !fieldsKey || fields.has(fieldsKey) || readingFields.current.has(fieldsKey)) {
      return;
    }
    readingFields.current.add(fieldsKey);
    const readOpening = opening.current;
    fetchTimeSeriesBreakdownFields(fieldsRequest.perspective, fieldsRequest.types).then((keys) => {
      // Kept for their own request only, whatever the widget asks meanwhile, until the editor is closed
      if (opening.current === readOpening) {
        readingFields.current.delete(fieldsKey);
        setFields((readFields) => new Map(readFields).set(fieldsKey, keys));
      }
    });
  }, [fieldsRequest, fieldsKey, fields]);

  return useMemo(() => {
    if (!enabled) {
      return NO_BREAKDOWN_STATE;
    }
    const keys = fieldsKey ? fields.get(fieldsKey) : undefined;
    let fieldsResolution: BreakdownResolution = 'loading';
    if (keys) {
      fieldsResolution = 'resolved';
    } else if (keys === null) {
      fieldsResolution = 'failed';
    }
    return getWidgetBreakdownState({
      filterKeysSchema,
      widget,
      host,
      savedFilter: savedFilterContent,
      fields: { resolution: fieldsResolution, keys },
      translate: t_i18n,
    });
  }, [enabled, filterKeysSchema, widget, host, savedFilterContent, fieldsKey, fields, t_i18n]);
};

export default useResolvedWidgetBreakdown;
