import React, { Suspense, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { graphql, PreloadedQuery, useMutation, usePaginationFragment, usePreloadedQuery, useSubscription } from 'react-relay';
import { useSearchParams } from 'react-router';
import type { GraphQLSubscriptionConfig } from 'relay-runtime';
import { useTheme } from '@mui/material/styles';
import { Text } from '@filigran/design-system';
import Button from '@common/button/Button';
import Card from '../../../../components/common/card/Card';
import Alert from '../../../../components/Alert';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { useFormatter } from '../../../../components/i18n';
import { fetchQuery, MESSAGING$ } from '../../../../relay/environment';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { useQueryLoadingWithLoadQuery } from '../../../../utils/hooks/useQueryLoading';
import ContainerTimelineAnchors from './ContainerTimelineAnchors';
import ContainerTimelineEventDrawer, { type TimelineEventDetails } from './ContainerTimelineEventDrawer';
import ContainerTimelineEventForm from './ContainerTimelineEventForm';
import ContainerTimelineLanes from './ContainerTimelineLanes';
import ContainerTimelineList from './ContainerTimelineList';
import ContainerTimelineSettingsDrawer from './ContainerTimelineSettingsDrawer';
import { ContainerTimelineEmptyState, ContainerTimelineErrorBoundary, ContainerTimelineSkeleton } from './ContainerTimelineStates';
import ContainerTimelineToolbar from './ContainerTimelineToolbar';
import useContainerTimelineExport from './useContainerTimelineExport';
import {
  containerTimelineUpdatedSubscription,
  notifyTimelineMutationErrors,
  timelineEventDeleteMutation,
  timelineEventEditMutation,
  timelineEventHideMutation,
  timelineEventPinMutation,
  timelineRegenerateMutation,
  timelineViewedMutation,
} from './ContainerTimelineMutations';
import type { ContainerTimelineSummaryQuery } from './__generated__/ContainerTimelineSummaryQuery.graphql';
import type { ContainerTimelineEventsQuery, ContainerTimelineEventsQuery$variables } from './__generated__/ContainerTimelineEventsQuery.graphql';
import type { ContainerTimelineEventsRefetchQuery } from './__generated__/ContainerTimelineEventsRefetchQuery.graphql';
import type { ContainerTimelineLinkedEventQuery } from './__generated__/ContainerTimelineLinkedEventQuery.graphql';
import type { ContainerTimelineEvents_data$key } from './__generated__/ContainerTimelineEvents_data.graphql';
import type { ContainerTimelineMutationsUpdatedSubscription } from './__generated__/ContainerTimelineMutationsUpdatedSubscription.graphql';
import type { ContainerTimelineMutationsPinMutation } from './__generated__/ContainerTimelineMutationsPinMutation.graphql';
import type { ContainerTimelineMutationsHideMutation } from './__generated__/ContainerTimelineMutationsHideMutation.graphql';
import type { ContainerTimelineMutationsEditMutation } from './__generated__/ContainerTimelineMutationsEditMutation.graphql';
import type { ContainerTimelineMutationsDeleteMutation } from './__generated__/ContainerTimelineMutationsDeleteMutation.graphql';
import type { ContainerTimelineMutationsRegenerateMutation } from './__generated__/ContainerTimelineMutationsRegenerateMutation.graphql';
import type { ContainerTimelineMutationsViewedMutation } from './__generated__/ContainerTimelineMutationsViewedMutation.graphql';
import {
  centerDomain,
  computeTimelineExtent,
  computeVisibleDomain,
  currentTimelineDomain,
  effectiveKinds,
  effectiveLanes,
  hasClearableTimelineFilters,
  isTimelineViewFilteredBy,
  parseTimelineViewState,
  serializeTimelineViewState,
  TIMELINE_ADD_MILESTONE_PARAM,
  TIMELINE_ANCHOR_KEYS,
  TIMELINE_LANES,
  TIMELINE_OPEN_SETTINGS_PARAM,
  type TimelineDomain,
  timelineExportWindow,
  type TimelineGrouping,
  type TimelineViewState,
  type TimelineZoomWindow,
  toTime,
  zoomDomain,
} from './timelineUtils';

const EVENTS_PAGE_SIZE = 500;
const URL_SYNC_DELAY = 300;

export const containerTimelineSummaryQuery = graphql`
  query ContainerTimelineSummaryQuery($id: String!) {
    containerTimelineSummary(id: $id) {
      container_id
      total
      manual_count
      pinned_count
      hidden_count
      first_event_time
      last_event_time
      anchors {
        first_adversary_activity
        first_detection
        first_response
        containment
        closure
        computed_at
      }
      settings {
        id
        enabled_lanes
        default_grouping
        default_zoom_window
        hidden_kinds
      }
      can_edit
      truncated
      generated_at
    }
  }
`;

export const containerTimelineEventsQuery = graphql`
  query ContainerTimelineEventsQuery(
    $id: String!
    $lanes: [TimelineLane!]
    $kinds: [TimelineEventKind!]
    $sources: [TimelineEventSource!]
    $search: String
    $includeHidden: Boolean
    $pinnedOnly: Boolean
    $count: Int!
    $cursor: ID
  ) {
    ...ContainerTimelineEvents_data
    @arguments(
      id: $id
      lanes: $lanes
      kinds: $kinds
      sources: $sources
      search: $search
      includeHidden: $includeHidden
      pinnedOnly: $pinnedOnly
      count: $count
      cursor: $cursor
    )
  }
`;

const containerTimelineLinkedEventQuery = graphql`
  query ContainerTimelineLinkedEventQuery($id: String!) {
    timelineEvent(id: $id) {
      id
      container_id
      event_time
    }
  }
`;

const containerTimelineEventsFragment = graphql`
  fragment ContainerTimelineEvents_data on Query
  @refetchable(queryName: "ContainerTimelineEventsRefetchQuery")
  @argumentDefinitions(
    id: { type: "String!" }
    lanes: { type: "[TimelineLane!]" }
    kinds: { type: "[TimelineEventKind!]" }
    sources: { type: "[TimelineEventSource!]" }
    search: { type: "String" }
    includeHidden: { type: "Boolean", defaultValue: false }
    pinnedOnly: { type: "Boolean", defaultValue: false }
    count: { type: "Int", defaultValue: 500 }
    cursor: { type: "ID" }
  ) {
    # Bounds of every event matching the same filters, so that the fit covers the events not loaded yet
    containerTimelineBounds(
      id: $id
      lanes: $lanes
      kinds: $kinds
      sources: $sources
      search: $search
      includeHidden: $includeHidden
      pinnedOnly: $pinnedOnly
    ) {
      first_event_time
      last_event_time
    }
    containerTimeline(
      id: $id
      lanes: $lanes
      kinds: $kinds
      sources: $sources
      search: $search
      includeHidden: $includeHidden
      pinnedOnly: $pinnedOnly
      orderMode: desc
      first: $count
      after: $cursor
    ) @connection(key: "ContainerTimelineEvents_containerTimeline") {
      pageInfo {
        globalCount
        hasNextPage
        endCursor
      }
      edges {
        node {
          id
          event_time
          event_end_time
          precision
          lane
          kind
          title
          description
          source
          rule_id
          element_id
          element_type
          pinned
          hidden
          annotation
          confidence
          ordering_hint
          external_id
          analyst_fields
          source_state {
            family
            state
            verdict
            validation
            run_id
            step
          }
          editable
          annotatable
          createdBy {
            ... on Identity {
              id
              entity_type
              name
            }
          }
          objectMarking {
            id
            definition_type
            definition
            x_opencti_order
            x_opencti_color
          }
          element {
            ... on BasicObject {
              id
              entity_type
            }
            ... on StixObject {
              representative {
                main
              }
            }
            ... on StixRelationship {
              id
              entity_type
              representative {
                main
              }
            }
            ... on StixCoreRelationship {
              relationship_type
              from {
                ... on BasicObject {
                  id
                  entity_type
                }
              }
              to {
                ... on BasicObject {
                  id
                  entity_type
                }
              }
            }
            ... on StixSightingRelationship {
              relationship_type
              from {
                ... on BasicObject {
                  id
                  entity_type
                }
              }
              to {
                ... on BasicObject {
                  id
                  entity_type
                }
              }
            }
          }
        }
      }
    }
  }
`;

type TimelineSummary = NonNullable<ContainerTimelineSummaryQuery['response']['containerTimelineSummary']>;

interface TimelineActions {
  togglePin: (event: TimelineEventDetails) => void;
  toggleHide: (event: TimelineEventDetails) => void;
  saveAnnotation: (event: TimelineEventDetails, annotation: string) => void;
  deleteEvent: (event: TimelineEventDetails) => void;
}

interface ContainerTimelineEventsViewProps {
  queryRef: PreloadedQuery<ContainerTimelineEventsQuery>;
  /** Event the timeline was opened on (URL link), still to be reached by loading earlier pages */
  linkedEventId: string | null;
  onLinkedEventResolved: () => void;
  summary: TimelineSummary;
  state: TimelineViewState;
  domain: TimelineDomain | null;
  lanes: readonly (typeof TIMELINE_LANES)[number][];
  onDomainChange: (domain: TimelineDomain | null) => void;
  onSelect: (eventId: string | null) => void;
  onEdit: (event: TimelineEventDetails) => void;
  onAdd: () => void;
  onRegenerate: () => void;
  onClearFilters: () => void;
  onOpenSettings: () => void;
  onVisibleDomainChange: (domain: TimelineDomain | null) => void;
  // Number of events matching the filters of the view, loaded or not
  onTotalChange: (total: number) => void;
  // Centering an event shows it in the lanes view, whatever the current view
  onCenter: (domain: TimelineDomain) => void;
  regenerating: boolean;
  actions: TimelineActions;
}

const ContainerTimelineEventsView = ({
  queryRef,
  linkedEventId,
  onLinkedEventResolved,
  summary,
  state,
  domain,
  lanes,
  onDomainChange,
  onSelect,
  onEdit,
  onAdd,
  onRegenerate,
  onClearFilters,
  onOpenSettings,
  onVisibleDomainChange,
  onTotalChange,
  onCenter,
  regenerating,
  actions,
}: ContainerTimelineEventsViewProps) => {
  const { t_i18n, n } = useFormatter();
  const theme = useTheme();
  const queryData = usePreloadedQuery<ContainerTimelineEventsQuery>(containerTimelineEventsQuery, queryRef);
  const { data, hasNext, loadNext, isLoadingNext } = usePaginationFragment<ContainerTimelineEventsRefetchQuery, ContainerTimelineEvents_data$key>(
    containerTimelineEventsFragment,
    queryData,
  );
  // Pages are loaded from the latest event backwards: the loaded events are displayed in chronological order
  const events = useMemo(() => (data.containerTimeline?.edges ?? []).map((edge) => {
    const node = edge.node;
    return {
      ...node,
      element_name: node.element?.representative?.main ?? null,
    } as TimelineEventDetails;
  }).reverse(), [data]);
  // Time of the event of the opening link: undefined while it loads, null when it is no event of this container
  const [linkedTime, setLinkedTime] = useState<number | null | undefined>(undefined);
  useEffect(() => {
    if (!linkedEventId) return undefined;
    let active = true;
    fetchQuery<ContainerTimelineLinkedEventQuery>(containerTimelineLinkedEventQuery, { id: linkedEventId })
      .toPromise()
      .then((result) => {
        const linked = result?.timelineEvent;
        if (active) setLinkedTime(linked && linked.container_id === summary.container_id ? toTime(linked.event_time) : null);
      })
      .catch(() => {
        if (active) setLinkedTime(null);
      });
    return () => {
      active = false;
    };
  }, [linkedEventId]);
  useEffect(() => {
    if (!linkedEventId) return;
    if (!hasNext || events.some((event) => event.id === linkedEventId)) {
      onLinkedEventResolved();
      return;
    }
    if (linkedTime === undefined) return;
    // Pages go back in time: once they reach before the event, the filters of the view leave it out
    const oldestLoaded = toTime(events[0]?.event_time);
    if (linkedTime === null || (oldestLoaded !== null && oldestLoaded < linkedTime)) {
      onLinkedEventResolved();
    } else if (!isLoadingNext) {
      loadNext(EVENTS_PAGE_SIZE);
    }
  }, [linkedEventId, linkedTime, events, hasNext, isLoadingNext]);
  const anchors = summary.anchors;
  // The fit spans every matching event, also the earlier ones not loaded yet ("Show earlier events" loads them)
  const firstTime = data.containerTimelineBounds?.first_event_time;
  const lastTime = data.containerTimelineBounds?.last_event_time;
  const extent = useMemo(
    () => computeTimelineExtent(events, [...TIMELINE_ANCHOR_KEYS.map((key) => anchors?.[key]), firstTime, lastTime]),
    [events, anchors, firstTime, lastTime],
  );
  const visibleDomain = domain ?? computeVisibleDomain(extent, state.zoom);
  const showsLanes = state.view === 'lanes' && events.length > 0;
  useEffect(() => {
    onVisibleDomainChange(showsLanes ? visibleDomain : null);
  }, [showsLanes, visibleDomain[0], visibleDomain[1]]);
  const selected = state.event ? events.find((event) => event.id === state.event) ?? null : null;
  const total = data.containerTimeline?.pageInfo.globalCount ?? events.length;
  useEffect(() => {
    onTotalChange(total);
  }, [total]);

  return (
    <>
      {events.length === 0 ? (
        <ContainerTimelineEmptyState
          filtered={summary.total > 0 && hasClearableTimelineFilters(state)}
          hiddenBySettings={summary.total > 0 && !hasClearableTimelineFilters(state)}
          canEdit={summary.can_edit}
          regenerating={regenerating}
          onAdd={onAdd}
          onRegenerate={onRegenerate}
          onClearFilters={onClearFilters}
          onOpenSettings={onOpenSettings}
        />
      ) : (
        <>
          {state.view === 'lanes' ? (
            <ContainerTimelineLanes
              events={events}
              lanes={lanes}
              domain={visibleDomain}
              grouping={state.grouping}
              anchors={anchors}
              selectedId={state.event}
              onDomainChange={onDomainChange}
              onFit={() => onDomainChange(null)}
              onSelect={onSelect}
              onClusterSelect={(clusterDomain) => onDomainChange(zoomDomain(clusterDomain, 1.2))}
              ariaLabel={t_i18n('Timeline of {count, plural, one {# event} other {# events}}', { values: { count: events.length } })}
            />
          ) : (
            <ContainerTimelineList
              events={events}
              grouping={state.grouping}
              selectedId={state.event}
              canEdit={summary.can_edit}
              onSelect={onSelect}
              onTogglePin={(event) => actions.togglePin(event as TimelineEventDetails)}
              onToggleHide={(event) => actions.toggleHide(event as TimelineEventDetails)}
            />
          )}
          <div style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(1.5), marginTop: theme.spacing(1.5) }}>
            <Text variant="content-caption" as="span">
              {t_i18n('{shown} of {total, plural, one {# event} other {# events}}', { values: { shown: n(events.length), total } })}
            </Text>
            {hasNext && (
              <Button variant="secondary" size="small" disabled={isLoadingNext} onClick={() => loadNext(EVENTS_PAGE_SIZE)} data-testid="timeline-load-more">
                {t_i18n('Show earlier events')}
              </Button>
            )}
          </div>
        </>
      )}
      <ContainerTimelineEventDrawer
        event={selected}
        canEdit={summary.can_edit}
        onClose={() => onSelect(null)}
        onTogglePin={actions.togglePin}
        onToggleHide={actions.toggleHide}
        onSaveAnnotation={actions.saveAnnotation}
        onEdit={onEdit}
        onDelete={actions.deleteEvent}
        onCenter={(event) => {
          const time = toTime(event.event_time);
          if (time !== null) onCenter(centerDomain(visibleDomain, time));
        }}
      />
    </>
  );
};

interface ContainerTimelineContentProps {
  containerId: string;
  containerName: string;
  summaryRef: PreloadedQuery<ContainerTimelineSummaryQuery>;
  reloadSummary: () => void;
}

const ContainerTimelineContent = ({ containerId, containerName, summaryRef, reloadSummary }: ContainerTimelineContentProps) => {
  const { t_i18n, nsdt } = useFormatter();
  const theme = useTheme();
  const { containerTimelineSummary: summary } = usePreloadedQuery<ContainerTimelineSummaryQuery>(containerTimelineSummaryQuery, summaryRef);
  const [searchParams, setSearchParams] = useSearchParams();
  const settings = summary?.settings;
  const defaults = useMemo(() => ({
    grouping: (settings?.default_grouping ?? 'day') as TimelineGrouping,
    zoom: (settings?.default_zoom_window ?? 'fit') as TimelineZoomWindow,
  }), [settings?.default_grouping, settings?.default_zoom_window]);
  const state = useMemo(() => parseTimelineViewState(searchParams, defaults), [searchParams, defaults]);
  // Pan and zoom move the domain continuously: it lives here and reaches the URL once settled
  const [domain, setDomain] = useState<TimelineDomain | null>(state.domain);
  const urlTimer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  const [liveUpdates, setLiveUpdates] = useState(0);
  const [formEvent, setFormEvent] = useState<TimelineEventDetails | null>(null);
  // Coming from "Add a milestone" or "Timeline settings" on the overview card: the form or the panel opens once, for users who may edit
  const [formOpen, setFormOpen] = useState(() => searchParams.has(TIMELINE_ADD_MILESTONE_PARAM) && !!summary?.can_edit);
  const [settingsOpen, setSettingsOpen] = useState(() => searchParams.has(TIMELINE_OPEN_SETTINGS_PARAM) && !!summary?.can_edit);
  const [regenerating, setRegenerating] = useState(false);
  const [visibleDomain, setVisibleDomain] = useState<TimelineDomain | null>(null);
  // The status names the events of the current view (filters included) once they are loaded
  const [viewTotal, setViewTotal] = useState<number | null>(null);
  // Only the event of the opening link is searched in earlier pages, never a later selection
  const [linkedEventId, setLinkedEventId] = useState<string | null>(state.event);

  // Patches apply to the URL as it is when they land: a delayed domain update never reverts a later change (view, filters)
  const updateState = useCallback((patch: Partial<TimelineViewState>) => {
    setSearchParams((current) => serializeTimelineViewState({ ...parseTimelineViewState(current, defaults), ...patch }, defaults), { replace: true });
  }, [defaults, setSearchParams]);

  useEffect(() => () => clearTimeout(urlTimer.current), []);
  useEffect(() => {
    if (!searchParams.has(TIMELINE_ADD_MILESTONE_PARAM) && !searchParams.has(TIMELINE_OPEN_SETTINGS_PARAM)) return;
    setSearchParams((current) => {
      const next = new URLSearchParams(current);
      next.delete(TIMELINE_ADD_MILESTONE_PARAM);
      next.delete(TIMELINE_OPEN_SETTINGS_PARAM);
      return next;
    }, { replace: true });
  }, []);
  // A new zoom window (or a URL change from the outside) resets the visible domain
  useEffect(() => {
    setDomain(state.domain);
  }, [state.zoom, state.domain?.[0], state.domain?.[1]]);

  const onDomainChange = useCallback((next: TimelineDomain | null) => {
    setDomain(next);
    clearTimeout(urlTimer.current);
    urlTimer.current = setTimeout(() => updateState({ domain: next }), URL_SYNC_DELAY);
  }, [updateState]);

  const lanes = useMemo(() => {
    // A selection kept in the URL stays within the lanes enabled in the settings, which apply to every user
    return effectiveLanes(state.lanes, settings?.enabled_lanes ?? []) ?? [...TIMELINE_LANES];
  }, [state.lanes, settings?.enabled_lanes]);
  const apiLanes = effectiveLanes(state.lanes, settings?.enabled_lanes ?? []);
  const apiKinds = effectiveKinds(state.kinds, settings?.hidden_kinds ?? []);
  const variables: ContainerTimelineEventsQuery$variables = {
    id: containerId,
    lanes: apiLanes,
    kinds: apiKinds as ContainerTimelineEventsQuery$variables['kinds'],
    sources: state.sources.length > 0 ? state.sources : null,
    search: state.search || null,
    includeHidden: state.includeHidden,
    pinnedOnly: state.pinnedOnly,
    count: EVENTS_PAGE_SIZE,
  };
  const [eventsRef, loadEvents] = useQueryLoadingWithLoadQuery<ContainerTimelineEventsQuery>(containerTimelineEventsQuery, variables);

  const refresh = useCallback(() => {
    setLiveUpdates(0);
    reloadSummary();
    loadEvents(variables, { fetchPolicy: 'network-only' });
  }, [reloadSummary, loadEvents, JSON.stringify(variables)]);

  // Live updates: other users and the timeline manager changing this timeline raise the badge
  const subscriptionConfig = useMemo<GraphQLSubscriptionConfig<ContainerTimelineMutationsUpdatedSubscription>>(() => ({
    subscription: containerTimelineUpdatedSubscription,
    variables: { id: containerId },
    onNext: (response) => {
      const update = response?.containerTimelineUpdated;
      if (update) setLiveUpdates((count) => count + Math.max(update.changed_event_ids.length, 1));
    },
  }), [containerId]);
  useSubscription(subscriptionConfig);

  const [commitPin] = useApiMutation<ContainerTimelineMutationsPinMutation>(timelineEventPinMutation);
  const [commitHide] = useApiMutation<ContainerTimelineMutationsHideMutation>(timelineEventHideMutation);
  const [commitEdit] = useApiMutation<ContainerTimelineMutationsEditMutation>(timelineEventEditMutation);
  const [commitDelete] = useApiMutation<ContainerTimelineMutationsDeleteMutation>(timelineEventDeleteMutation);
  const [commitRegenerate] = useApiMutation<ContainerTimelineMutationsRegenerateMutation>(timelineRegenerateMutation);

  const actions: TimelineActions = {
    togglePin: (event) => commitPin({
      variables: { id: event.id, pinned: !event.pinned },
      onCompleted: (_, errors) => {
        if (notifyTimelineMutationErrors(errors)) return;
        if (!isTimelineViewFilteredBy('pin', state)) {
          reloadSummary();
          return;
        }
        if (event.pinned) updateState({ event: null });
        refresh();
      },
    }),
    toggleHide: (event) => commitHide({
      variables: { id: event.id, hidden: !event.hidden },
      onCompleted: (_, errors) => {
        if (notifyTimelineMutationErrors(errors)) return;
        if (!state.includeHidden && !event.hidden) updateState({ event: null });
        refresh();
      },
    }),
    saveAnnotation: (event, annotation) => commitEdit({
      variables: { id: event.id, input: { annotation: annotation.trim() || null } },
      onCompleted: (_, errors) => {
        if (notifyTimelineMutationErrors(errors)) return;
        MESSAGING$.notifySuccess(t_i18n('The annotation has been saved'));
        if (isTimelineViewFilteredBy('annotation', state)) refresh();
      },
    }),
    deleteEvent: (event) => commitDelete({
      variables: { id: event.id },
      onCompleted: (_, errors) => {
        if (notifyTimelineMutationErrors(errors)) return;
        updateState({ event: null });
        refresh();
      },
    }),
  };

  const regenerate = () => {
    setRegenerating(true);
    commitRegenerate({
      variables: { containerId },
      onCompleted: (response, errors) => {
        setRegenerating(false);
        if (notifyTimelineMutationErrors(errors)) return;
        const result = response.timelineRegenerate;
        MESSAGING$.notifySuccess(t_i18n('Timeline regenerated: {created} new, {updated} updated, {deleted} removed events', {
          values: { created: result?.created_count ?? 0, updated: result?.updated_count ?? 0, deleted: result?.deleted_count ?? 0 },
        }));
        refresh();
      },
      onError: () => setRegenerating(false),
    });
  };

  const exportWindow = timelineExportWindow(state.view, state.zoom, domain, visibleDomain);
  const { exportTimeline } = useContainerTimelineExport({
    containerId,
    containerName,
    filters: {
      lanes: apiLanes,
      kinds: apiKinds,
      sources: state.sources,
      search: state.search,
      includeHidden: state.includeHidden,
      pinnedOnly: state.pinnedOnly,
      from: exportWindow ? new Date(exportWindow[0]).toISOString() : null,
      to: exportWindow ? new Date(exportWindow[1]).toISOString() : null,
    },
  });

  if (!summary || !settings) {
    return <Alert severity="warning" content={t_i18n('This timeline is not available')} />;
  }

  return (
    <div data-testid="container-timeline">
      <ContainerTimelineAnchors
        anchors={summary.anchors}
        onAnchorClick={(time) => {
          const centered = centerDomain(currentTimelineDomain(domain, visibleDomain, state.zoom), time);
          clearTimeout(urlTimer.current);
          setDomain(centered);
          updateState({ view: 'lanes', domain: centered });
        }}
      />
      <Text variant="content-caption" as="div" style={{ marginTop: theme.spacing(1) }} data-testid="timeline-status">
        {t_i18n('{count, plural, one {# event} other {# events}}', { values: { count: viewTotal ?? summary.total } })}
        {summary.generated_at && ` - ${t_i18n('Last update')} ${nsdt(summary.generated_at)}`}
      </Text>
      {summary.truncated && (
        <div style={{ marginTop: theme.spacing(1.5) }}>
          <Alert
            severity="info"
            content={t_i18n('This case is very large: its timeline is built from a bounded number of objects and history entries, so some events may be missing. Administrators can raise these limits in the timeline manager configuration.')}
          />
        </div>
      )}
      <Card sx={{ marginTop: 2 }}>
        <ContainerTimelineToolbar
          state={state}
          onChange={updateState}
          enabledLanes={settings.enabled_lanes}
          canEdit={summary.can_edit}
          liveUpdates={liveUpdates}
          regenerating={regenerating}
          onRefresh={refresh}
          onAdd={() => {
            setFormEvent(null);
            setFormOpen(true);
          }}
          onExport={exportTimeline}
          onOpenSettings={() => setSettingsOpen(true)}
          onRegenerate={regenerate}
          onZoom={(factor) => onDomainChange(zoomDomain(currentTimelineDomain(domain, visibleDomain, state.zoom), factor))}
          onFit={() => onDomainChange(null)}
          visibleDomain={visibleDomain}
        />
        {eventsRef ? (
          <ContainerTimelineErrorBoundary onRetry={refresh}>
            <Suspense fallback={<ContainerTimelineSkeleton />}>
              <ContainerTimelineEventsView
                queryRef={eventsRef}
                linkedEventId={linkedEventId}
                onLinkedEventResolved={() => setLinkedEventId(null)}
                summary={summary}
                state={state}
                domain={domain}
                lanes={lanes}
                onDomainChange={onDomainChange}
                onSelect={(eventId) => updateState({ event: eventId })}
                onEdit={(event) => {
                  setFormEvent(event);
                  setFormOpen(true);
                }}
                onAdd={() => {
                  setFormEvent(null);
                  setFormOpen(true);
                }}
                onRegenerate={regenerate}
                onClearFilters={() => updateState({ lanes: [], kinds: [], sources: [], search: '', includeHidden: false, pinnedOnly: false })}
                onOpenSettings={() => setSettingsOpen(true)}
                onVisibleDomainChange={setVisibleDomain}
                onTotalChange={setViewTotal}
                onCenter={(centered) => {
                  clearTimeout(urlTimer.current);
                  setDomain(centered);
                  updateState({ view: 'lanes', domain: centered });
                }}
                regenerating={regenerating}
                actions={actions}
              />
            </Suspense>
          </ContainerTimelineErrorBoundary>
        ) : (
          <ContainerTimelineSkeleton />
        )}
      </Card>
      <ContainerTimelineEventForm
        containerId={containerId}
        open={formOpen}
        event={formEvent}
        onClose={() => setFormOpen(false)}
        onSaved={refresh}
      />
      <ContainerTimelineSettingsDrawer
        containerId={containerId}
        open={settingsOpen}
        settings={settings}
        onClose={() => setSettingsOpen(false)}
        onSaved={refresh}
      />
    </div>
  );
};

interface ContainerTimelineProps {
  containerId: string;
  containerName: string;
}

const ContainerTimelineOfContainer = ({ containerId, containerName }: ContainerTimelineProps) => {
  const [summaryRef, loadSummary] = useQueryLoadingWithLoadQuery<ContainerTimelineSummaryQuery>(containerTimelineSummaryQuery, { id: containerId });
  const reloadSummary = useCallback(() => loadSummary({ id: containerId }, { fetchPolicy: 'network-only' }), [loadSummary, containerId]);
  // Usage telemetry: one opening of the tab (the strip and the widget read the same summary without counting)
  const [commitViewed] = useMutation<ContainerTimelineMutationsViewedMutation>(timelineViewedMutation);
  useEffect(() => {
    commitViewed({ variables: { containerId }, onError: () => undefined });
  }, [containerId]);
  if (!summaryRef) return <Loader variant={LoaderVariant.container} />;
  return (
    <Suspense fallback={<Loader variant={LoaderVariant.container} />}>
      <ContainerTimelineContent containerId={containerId} containerName={containerName} summaryRef={summaryRef} reloadSummary={reloadSummary} />
    </Suspense>
  );
};

/**
 * Timeline tab of an Incident or a Case (Incident response, Request for information, Request for takedown). The route
 * keeps the component from one container to the next: keyed by the container, each one starts with its own state.
 */
const ContainerTimeline = ({ containerId, containerName }: ContainerTimelineProps) => (
  <ContainerTimelineOfContainer key={containerId} containerId={containerId} containerName={containerName} />
);

export default ContainerTimeline;
