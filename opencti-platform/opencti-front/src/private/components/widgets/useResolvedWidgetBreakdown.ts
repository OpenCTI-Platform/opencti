import { useEffect, useMemo, useRef, useState } from 'react';
import useAuth from '../../../utils/hooks/useAuth';
import { useFormatter } from '../../../components/i18n';
import type { Widget, WidgetHost, WidgetParameters } from '../../../utils/widget/widget';
import type { FilterGroup } from '../../../utils/filters/filtersHelpers-types';
import {
  type BreakdownFieldsRequest,
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

const NO_ANSWERS: ReadonlyMap<string, never> = new Map<string, never>();

/**
 * Answers the editor reads from the API while it is open (`isOpen`), by the key of their request. Each `request` is
 * read once per opening for its `requestKey`: its answer is kept until the editor closes, the one of a failed read
 * included, which is then not read again. A read still running is not started again, even after the editor stopped
 * asking for it, and its answer is kept for its own key whatever the editor asks meanwhile. The answer of a read
 * started in a previous opening is dropped: what the API answers may have changed in between.
 */
const useReadOncePerOpening = <TRequest, TAnswer>({ isOpen, request, requestKey, read }: {
  isOpen: boolean;
  // What to read, null when nothing is to be read
  request: TRequest | null;
  requestKey: string | null;
  read: (request: TRequest) => Promise<TAnswer>;
}): ReadonlyMap<string, TAnswer> => {
  const [answers, setAnswers] = useState<ReadonlyMap<string, TAnswer>>(NO_ANSWERS);
  // The keys of the reads still running
  const readingKeys = useRef(new Set<string>());
  // Counts the openings of the editor
  const openingCount = useRef(0);
  useEffect(() => {
    if (!isOpen) {
      openingCount.current += 1;
      readingKeys.current.clear();
      setAnswers(NO_ANSWERS);
    }
  }, [isOpen]);
  useEffect(() => {
    if (request === null || requestKey === null || answers.has(requestKey) || readingKeys.current.has(requestKey)) {
      return;
    }
    readingKeys.current.add(requestKey);
    const readOpening = openingCount.current;
    read(request).then((answer) => {
      if (openingCount.current === readOpening) {
        readingKeys.current.delete(requestKey);
        setAnswers((readAnswers) => new Map(readAnswers).set(requestKey, answer));
      }
    });
  }, [request, requestKey, answers, read]);
  return answers;
};

const readSavedFilter = (savedFilterId: string): Promise<FilterGroup | null> => fetchSavedFilterContent(savedFilterId);
const readBreakdownFields = ({ perspective, types }: BreakdownFieldsRequest) => fetchTimeSeriesBreakdownFields(perspective, types);

/**
 * Breakdown of the edited widget (getWidgetBreakdownState), derived by the editor provider for all its steps:
 * the saved filter of the dataset is read once per opening, whatever the widget becomes meanwhile, and then the
 * fields the API lists for the dataset, once per opening for each perspective and types it reads.
 * Without `enabled` (the feature off, or the editor closed), no breakdown is shown, nor kept or dropped.
 */
const useResolvedWidgetBreakdown = (widget: EditedWidget, host: WidgetHost, enabled: boolean): WidgetBreakdownState => {
  const { schema: { filterKeysSchema } } = useAuth();
  const { t_i18n } = useFormatter();
  const variables = useOptionalDashboardVariableDefinitions();
  const savedFilterId = widget.dataSelection[0]?.filters_id ?? null;
  const isSavedFilterNeeded = enabled && !!savedFilterId && getBreakdownEditorState(widget, host) !== 'hidden';
  // The filters of each saved filter read, null for one that cannot be read or holds none
  const savedFilters = useReadOncePerOpening({
    isOpen: enabled,
    request: isSavedFilterNeeded ? savedFilterId : null,
    requestKey: savedFilterId,
    read: readSavedFilter,
  });
  const savedFilterContent = useMemo(() => {
    // A saved filter that cannot be read, or holds no filters, leaves the types of the dataset unknown
    let resolution: BreakdownResolution = 'resolved';
    const filters = savedFilterId ? savedFilters.get(savedFilterId) : undefined;
    if (savedFilterId) {
      if (filters === undefined) {
        resolution = 'loading';
      } else if (!filters) {
        resolution = 'failed';
      }
    }
    return { resolution, filters };
  }, [savedFilterId, savedFilters]);
  // The fields of the dataset, asked once it is known
  const fieldsRequest = useMemo(
    () => (enabled ? getBreakdownFieldsRequest({ widget, host, savedFilter: savedFilterContent, variables }) : null),
    [enabled, widget, host, savedFilterContent, variables],
  );
  const fieldsRequestKey = fieldsRequest ? JSON.stringify(fieldsRequest) : null;
  // The keys of the fields read for each request, null for a request that failed
  const fields = useReadOncePerOpening({ isOpen: enabled, request: fieldsRequest, requestKey: fieldsRequestKey, read: readBreakdownFields });

  return useMemo(() => {
    if (!enabled) {
      return NO_BREAKDOWN_STATE;
    }
    const keys = fieldsRequestKey ? fields.get(fieldsRequestKey) : undefined;
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
  }, [enabled, filterKeysSchema, widget, host, savedFilterContent, fieldsRequestKey, fields, t_i18n]);
};

export default useResolvedWidgetBreakdown;
