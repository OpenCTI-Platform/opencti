import React, { Suspense, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { graphql, PreloadedQuery, usePaginationFragment, usePreloadedQuery, useSubscription } from 'react-relay';
import { useSearchParams } from 'react-router';
import type { GraphQLSubscriptionConfig } from 'relay-runtime';
import Button from '@common/button/Button';
import Card from '../../../../components/common/card/Card';
import Alert from '../../../../components/Alert';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { useFormatter } from '../../../../components/i18n';
import { MESSAGING$ } from '../../../../relay/environment';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { useQueryLoadingWithLoadQuery } from '../../../../utils/hooks/useQueryLoading';
import ContainerTimelineAnchors from './ContainerTimelineAnchors';
import ContainerTimelineEventDrawer, { type TimelineEventDetails } from './ContainerTimelineEventDrawer';
import ContainerTimelineEventForm from './ContainerTimelineEventForm';
import ContainerTimelineLanes from './ContainerTimelineLanes';
import ContainerTimelineList from './ContainerTimelineList';
import ContainerTimelineSettingsDialog from './ContainerTimelineSettingsDialog';
import ContainerTimelineToolbar from './ContainerTimelineToolbar';
import useContainerTimelineExport from './useContainerTimelineExport';
import {
  containerTimelineUpdatedSubscription,
  timelineEventDeleteMutation,
  timelineEventEditMutation,
  timelineEventHideMutation,
  timelineEventPinMutation,
  timelineRegenerateMutation,
} from './ContainerTimelineMutations';
import type { ContainerTimelineSummaryQuery } from './__generated__/ContainerTimelineSummaryQuery.graphql';
import type { ContainerTimelineEventsQuery, ContainerTimelineEventsQuery$variables } from './__generated__/ContainerTimelineEventsQuery.graphql';
import type { ContainerTimelineEventsRefetchQuery } from './__generated__/ContainerTimelineEventsRefetchQuery.graphql';
import type { ContainerTimelineEvents_data$key } from './__generated__/ContainerTimelineEvents_data.graphql';
import type { ContainerTimelineMutationsUpdatedSubscription } from './__generated__/ContainerTimelineMutationsUpdatedSubscription.graphql';
import type { ContainerTimelineMutationsPinMutation } from './__generated__/ContainerTimelineMutationsPinMutation.graphql';
import type { ContainerTimelineMutationsHideMutation } from './__generated__/ContainerTimelineMutationsHideMutation.graphql';
import type { ContainerTimelineMutationsEditMutation } from './__generated__/ContainerTimelineMutationsEditMutation.graphql';
import type { ContainerTimelineMutationsDeleteMutation } from './__generated__/ContainerTimelineMutationsDeleteMutation.graphql';
import type { ContainerTimelineMutationsRegenerateMutation } from './__generated__/ContainerTimelineMutationsRegenerateMutation.graphql';
import {
  centerDomain,
  computeTimelineExtent,
  computeVisibleDomain,
  effectiveKinds,
  effectiveLanes,
  parseTimelineViewState,
  serializeTimelineViewState,
  TIMELINE_ANCHOR_KEYS,
  TIMELINE_LANES,
  type TimelineDomain,
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
    containerTimeline(
      id: $id
      lanes: $lanes
      kinds: $kinds
      sources: $sources
      search: $search
      includeHidden: $includeHidden
      pinnedOnly: $pinnedOnly
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
          editable
          createdBy {
            ... on Identity {
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
  summary: TimelineSummary;
  state: TimelineViewState;
  domain: TimelineDomain | null;
  lanes: readonly (typeof TIMELINE_LANES)[number][];
  svgRef: React.RefObject<SVGSVGElement | null>;
  onDomainChange: (domain: TimelineDomain | null) => void;
  onSelect: (eventId: string | null) => void;
  onEdit: (event: TimelineEventDetails) => void;
  actions: TimelineActions;
}

const ContainerTimelineEventsView = ({
  queryRef,
  summary,
  state,
  domain,
  lanes,
  svgRef,
  onDomainChange,
  onSelect,
  onEdit,
  actions,
}: ContainerTimelineEventsViewProps) => {
  const { t_i18n, n } = useFormatter();
  const queryData = usePreloadedQuery<ContainerTimelineEventsQuery>(containerTimelineEventsQuery, queryRef);
  const { data, hasNext, loadNext, isLoadingNext } = usePaginationFragment<ContainerTimelineEventsRefetchQuery, ContainerTimelineEvents_data$key>(
    containerTimelineEventsFragment,
    queryData,
  );
  const events = useMemo(() => (data.containerTimeline?.edges ?? []).map((edge) => {
    const node = edge.node;
    return {
      ...node,
      element_name: node.element?.representative?.main ?? null,
    } as TimelineEventDetails;
  }), [data]);
  const anchors = summary.anchors;
  const extent = useMemo(() => computeTimelineExtent(events, TIMELINE_ANCHOR_KEYS.map((key) => anchors?.[key])), [events, anchors]);
  const visibleDomain = domain ?? computeVisibleDomain(extent, state.zoom);
  const selected = state.event ? events.find((event) => event.id === state.event) ?? null : null;
  const total = data.containerTimeline?.pageInfo.globalCount ?? events.length;

  return (
    <>
      {events.length === 0 ? (
        <div style={{ padding: 30, textAlign: 'center' }} data-testid="timeline-empty">
          {summary.total === 0 ? t_i18n('This timeline has no event yet') : t_i18n('No event matches the current filters')}
        </div>
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
              svgRef={svgRef}
              ariaLabel={t_i18n('Timeline of {count} events', { values: { count: events.length } })}
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
          <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginTop: 12 }}>
            <span style={{ fontSize: 12 }}>
              {t_i18n('{shown} of {total} events', { values: { shown: n(events.length), total: n(total) } })}
            </span>
            {hasNext && (
              <Button variant="secondary" size="small" disabled={isLoadingNext} onClick={() => loadNext(EVENTS_PAGE_SIZE)} data-testid="timeline-load-more">
                {t_i18n('Show more events')}
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
          if (time !== null) onDomainChange(centerDomain(visibleDomain, time));
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
  const { t_i18n } = useFormatter();
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
  const svgRef = useRef<SVGSVGElement>(null);
  const [liveUpdates, setLiveUpdates] = useState(0);
  const [formEvent, setFormEvent] = useState<TimelineEventDetails | null>(null);
  const [formOpen, setFormOpen] = useState(false);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [regenerating, setRegenerating] = useState(false);

  const updateState = useCallback((patch: Partial<TimelineViewState>) => {
    setSearchParams(serializeTimelineViewState({ ...state, ...patch }, defaults), { replace: true });
  }, [state, defaults, setSearchParams]);

  useEffect(() => () => clearTimeout(urlTimer.current), []);
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
    const enabled = TIMELINE_LANES.filter((lane) => (settings?.enabled_lanes ?? TIMELINE_LANES).includes(lane));
    return state.lanes.length > 0 ? TIMELINE_LANES.filter((lane) => state.lanes.includes(lane)) : enabled;
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
    togglePin: (event) => commitPin({ variables: { id: event.id, pinned: !event.pinned }, onCompleted: () => reloadSummary() }),
    toggleHide: (event) => commitHide({
      variables: { id: event.id, hidden: !event.hidden },
      onCompleted: () => {
        if (!state.includeHidden && !event.hidden) updateState({ event: null });
        refresh();
      },
    }),
    saveAnnotation: (event, annotation) => commitEdit({
      variables: { id: event.id, input: { annotation: annotation.trim() || null } },
      onCompleted: () => MESSAGING$.notifySuccess(t_i18n('The annotation has been saved')),
    }),
    deleteEvent: (event) => commitDelete({
      variables: { id: event.id },
      onCompleted: () => {
        updateState({ event: null });
        refresh();
      },
    }),
  };

  const regenerate = () => {
    setRegenerating(true);
    commitRegenerate({
      variables: { containerId },
      onCompleted: (response) => {
        setRegenerating(false);
        const result = response.timelineRegenerate;
        MESSAGING$.notifySuccess(t_i18n('Timeline regenerated: {created} new, {updated} updated, {deleted} removed events', {
          values: { created: result?.created_count ?? 0, updated: result?.updated_count ?? 0, deleted: result?.deleted_count ?? 0 },
        }));
        refresh();
      },
      onError: () => setRegenerating(false),
    });
  };

  const { exportTimeline } = useContainerTimelineExport({
    containerId,
    containerName,
    lanes: apiLanes,
    kinds: apiKinds,
    includeHidden: state.includeHidden,
    svgRef,
  });

  if (!summary || !settings) {
    return <Alert severity="warning" content={t_i18n('This timeline is not available')} />;
  }

  return (
    <div data-testid="container-timeline">
      <ContainerTimelineAnchors
        anchors={summary.anchors}
        onAnchorClick={(time) => {
          updateState({ view: 'lanes' });
          const current = domain ?? computeVisibleDomain(null, state.zoom);
          onDomainChange(centerDomain(current, time));
        }}
      />
      {summary.truncated && (
        <div style={{ marginTop: 12 }}>
          <Alert severity="info" content={t_i18n('This case is very large: its timeline is built from a bounded number of objects and history entries.')} />
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
          onZoom={(factor) => onDomainChange(zoomDomain(domain ?? computeVisibleDomain(null, state.zoom), factor))}
          onFit={() => onDomainChange(null)}
        />
        {eventsRef ? (
          <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
            <ContainerTimelineEventsView
              queryRef={eventsRef}
              summary={summary}
              state={state}
              domain={domain}
              lanes={lanes}
              svgRef={svgRef}
              onDomainChange={onDomainChange}
              onSelect={(eventId) => updateState({ event: eventId })}
              onEdit={(event) => {
                setFormEvent(event);
                setFormOpen(true);
              }}
              actions={actions}
            />
          </Suspense>
        ) : (
          <Loader variant={LoaderVariant.inElement} />
        )}
      </Card>
      <ContainerTimelineEventForm
        containerId={containerId}
        open={formOpen}
        event={formEvent}
        onClose={() => setFormOpen(false)}
        onSaved={refresh}
      />
      <ContainerTimelineSettingsDialog
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

/** Timeline tab of an Incident or a Case (Incident response, Request for information, Request for takedown). */
const ContainerTimeline = ({ containerId, containerName }: ContainerTimelineProps) => {
  const [summaryRef, loadSummary] = useQueryLoadingWithLoadQuery<ContainerTimelineSummaryQuery>(containerTimelineSummaryQuery, { id: containerId });
  const reloadSummary = useCallback(() => loadSummary({ id: containerId }, { fetchPolicy: 'network-only' }), [loadSummary, containerId]);
  if (!summaryRef) return <Loader variant={LoaderVariant.container} />;
  return (
    <Suspense fallback={<Loader variant={LoaderVariant.container} />}>
      <ContainerTimelineContent containerId={containerId} containerName={containerName} summaryRef={summaryRef} reloadSummary={reloadSummary} />
    </Suspense>
  );
};

export default ContainerTimeline;
