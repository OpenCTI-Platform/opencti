import React, { CSSProperties, ReactNode, Suspense, useMemo } from 'react';
import { graphql, PreloadedQuery, useLazyLoadQuery, usePreloadedQuery } from 'react-relay';
import { Link, useNavigate } from 'react-router';
import { useTheme } from '@mui/material/styles';
import { Text } from '@filigran/design-system';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { useFormatter } from '../../../../components/i18n';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { resolveLink } from '../../../../utils/Entity';
import ContainerTimelineLanes, { type TimelineChartAnchors } from './ContainerTimelineLanes';
import type { ContainerTimelineWidgetQuery } from './__generated__/ContainerTimelineWidgetQuery.graphql';
import type {
  ContainerTimelineWidgetEventsQuery,
  TimelineEventKind as GqlTimelineEventKind,
  TimelineLane as GqlTimelineLane,
} from './__generated__/ContainerTimelineWidgetEventsQuery.graphql';
import {
  computeTimelineExtent,
  computeVisibleDomain,
  effectiveKinds,
  effectiveLanes,
  TIMELINE_ANCHOR_KEYS,
  TIMELINE_LANES,
  TIMELINE_ZOOM_WINDOWS,
  type TimelineGrouping,
  type TimelineLane,
  type TimelineZoomWindow,
} from './timelineUtils';

const WIDGET_EVENTS = 500;

export interface ContainerTimelineWidgetParameters {
  title?: string | null;
  container_id?: string | null;
  timeline_lanes?: readonly string[] | null;
  timeline_window?: string | null;
}

export const containerTimelineWidgetQuery = graphql`
  query ContainerTimelineWidgetQuery($id: String!) {
    stixDomainObject(id: $id) {
      id
      entity_type
      representative {
        main
      }
    }
    containerTimelineSummary(id: $id) {
      anchors {
        first_adversary_activity
        first_detection
        first_response
        containment
        closure
      }
      settings {
        id
        enabled_lanes
        hidden_kinds
        default_grouping
      }
    }
  }
`;

// The lanes disabled and the kinds hidden in the timeline settings are left out before the limit, so they never displace the others
const containerTimelineWidgetEventsQuery = graphql`
  query ContainerTimelineWidgetEventsQuery($id: String!, $lanes: [TimelineLane!], $kinds: [TimelineEventKind!], $count: Int!) {
    shown: containerTimelineSummary(id: $id, lanes: $lanes, kinds: $kinds) {
      first_event_time
      last_event_time
    }
    containerTimeline(id: $id, lanes: $lanes, kinds: $kinds, first: $count, orderMode: desc) {
      pageInfo {
        globalCount
      }
      edges {
        node {
          id
          event_time
          event_end_time
          open_ended
          precision
          lane
          kind
          title
          pinned
          hidden
          source
          annotation
        }
      }
    }
  }
`;

// The widget is drawn in its container once the case is known, so that its default title can name the case
type RenderWidget = (title: string | null, children: ReactNode) => React.ReactElement;

interface ContainerTimelineWidgetEventsProps {
  containerId: string;
  containerName: string;
  timelinePath: string;
  lanes: readonly TimelineLane[];
  enabledLanes: readonly string[];
  hiddenKinds: readonly string[];
  zoomWindow: TimelineZoomWindow;
  grouping: TimelineGrouping;
  anchors: TimelineChartAnchors;
}

const ContainerTimelineWidgetEvents = ({
  containerId,
  containerName,
  timelinePath,
  lanes,
  enabledLanes,
  hiddenKinds,
  zoomWindow,
  grouping,
  anchors,
}: ContainerTimelineWidgetEventsProps) => {
  const { t_i18n, n } = useFormatter();
  const theme = useTheme();
  const navigate = useNavigate();
  const apiLanes = effectiveLanes([...lanes], enabledLanes);
  const { containerTimeline, shown } = useLazyLoadQuery<ContainerTimelineWidgetEventsQuery>(
    containerTimelineWidgetEventsQuery,
    {
      id: containerId,
      lanes: apiLanes as GqlTimelineLane[] | null,
      kinds: effectiveKinds([], hiddenKinds) as GqlTimelineEventKind[] | null,
      count: WIDGET_EVENTS,
    },
  );
  // The latest events of the timeline (the window of the widget ends at the last one), in chronological order
  const events = useMemo(() => (containerTimeline?.edges ?? []).map((edge) => edge.node).reverse(), [containerTimeline]);
  if (events.length === 0) {
    return <WidgetNoData message={t_i18n('No event in this period')} />;
  }
  const shownLanes = (apiLanes ?? TIMELINE_LANES).filter((lane) => events.some((e) => e.lane === lane));
  // The whole timeline of the shown lanes and kinds, also the events older than the latest ones drawn here
  const extent = computeTimelineExtent(events, [...TIMELINE_ANCHOR_KEYS.map((key) => anchors?.[key]), shown?.first_event_time, shown?.last_event_time]);
  // A long timeline is drawn from its latest events: the count says so, the full timeline is one click away
  const total = containerTimeline?.pageInfo.globalCount ?? events.length;
  return (
    <>
      <ContainerTimelineLanes
        events={events}
        lanes={shownLanes}
        domain={computeVisibleDomain(extent, zoomWindow)}
        grouping={grouping}
        anchors={anchors}
        onSelect={(eventId) => navigate(`${timelinePath}?event=${encodeURIComponent(eventId)}`)}
        ariaLabel={t_i18n('Timeline of {name}', { values: { name: containerName } })}
      />
      {total > events.length && (
        <Text variant="content-caption" as="div" style={{ marginTop: theme.spacing(0.5) }} data-testid="timeline-widget-truncated">
          {t_i18n('{shown} of {total, plural, one {# event} other {# events}}', { values: { shown: n(events.length), total } })}
        </Text>
      )}
    </>
  );
};

interface ContainerTimelineWidgetContentProps {
  queryRef: PreloadedQuery<ContainerTimelineWidgetQuery>;
  lanes: readonly TimelineLane[];
  zoomWindow: TimelineZoomWindow;
  renderWidget: RenderWidget;
}

const ContainerTimelineWidgetContent = ({ queryRef, lanes, zoomWindow, renderWidget }: ContainerTimelineWidgetContentProps) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme();
  const { stixDomainObject: container, containerTimelineSummary: summary } = usePreloadedQuery<ContainerTimelineWidgetQuery>(
    containerTimelineWidgetQuery,
    queryRef,
  );
  if (!container || !summary) {
    return renderWidget(null, <WidgetNoData message={t_i18n('The selected incident or case is not available')} />);
  }
  // Card titles are capitalized: the case and the period are named on the first line of the widget, as typed
  const caption = t_i18n(
    'Timeline of {name} - {window, select, fit {whole timeline} day {last day of events} week {last week of events} month {last month of events} quarter {last quarter of events} other {last year of events}}',
    { values: { name: container.representative.main, window: zoomWindow } },
  );
  const timelinePath = `${resolveLink(container.entity_type)}/${container.id}/timeline`;
  // Lanes chosen in the widget stay within the lanes enabled in the timeline settings of the case
  const enabledLanes = TIMELINE_LANES.filter((lane) => summary.settings.enabled_lanes.includes(lane));
  const widgetLanes = lanes.filter((lane) => enabledLanes.includes(lane));
  if (lanes.length > 0 && widgetLanes.length === 0) {
    return renderWidget(null, <WidgetNoData message={t_i18n('No event in this period')} />);
  }
  return renderWidget(null, (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', minHeight: 0 }}>
      <Text variant="content-caption" as="div" style={{ marginBottom: theme.spacing(1), whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }} title={caption}>
        <Link to={timelinePath} data-testid="timeline-widget-caption">{caption}</Link>
      </Text>
      <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
        <ContainerTimelineWidgetEvents
          containerId={container.id}
          containerName={container.representative.main}
          timelinePath={timelinePath}
          lanes={widgetLanes}
          enabledLanes={summary.settings.enabled_lanes}
          hiddenKinds={summary.settings.hidden_kinds}
          zoomWindow={zoomWindow}
          grouping={(summary.settings.default_grouping ?? 'day') as TimelineGrouping}
          anchors={summary.anchors}
        />
      </Suspense>
    </div>
  ));
};

interface ContainerTimelineWidgetProps {
  parameters?: ContainerTimelineWidgetParameters | null;
  popover?: ReactNode;
  height?: CSSProperties['height'];
  variant?: string;
}

interface ContainerTimelineWidgetLoaderProps {
  containerId: string;
  lanes: readonly TimelineLane[];
  zoomWindow: TimelineZoomWindow;
  renderWidget: RenderWidget;
}

const ContainerTimelineWidgetLoader = ({ containerId, lanes, zoomWindow, renderWidget }: ContainerTimelineWidgetLoaderProps) => {
  const queryRef = useQueryLoading<ContainerTimelineWidgetQuery>(containerTimelineWidgetQuery, { id: containerId });
  const loading = renderWidget(null, <Loader variant={LoaderVariant.inElement} />);
  if (!queryRef) return loading;
  return (
    <Suspense fallback={loading}>
      <ContainerTimelineWidgetContent queryRef={queryRef} lanes={lanes} zoomWindow={zoomWindow} renderWidget={renderWidget} />
    </Suspense>
  );
};

/** Dashboard widget: the timeline of one incident or case, restricted to some lanes and to a window. */
const ContainerTimelineWidget = ({ parameters, popover, height, variant }: ContainerTimelineWidgetProps) => {
  const { t_i18n } = useFormatter();
  const lanes = (parameters?.timeline_lanes ?? []).filter((lane): lane is TimelineLane => (TIMELINE_LANES as readonly string[]).includes(lane));
  const zoomWindow = (TIMELINE_ZOOM_WINDOWS as readonly string[]).includes(parameters?.timeline_window ?? '')
    ? parameters?.timeline_window as TimelineZoomWindow
    : 'fit';
  // A title set in the widget parameters always wins over the default one
  const renderWidget: RenderWidget = (title, children) => (
    <WidgetContainer height={height} variant={variant} title={parameters?.title || title || t_i18n('Incident and case timeline')} action={popover}>
      {children}
    </WidgetContainer>
  );
  if (!parameters?.container_id) {
    return renderWidget(null, <WidgetNoData message={t_i18n('Select an incident or a case in the widget parameters')} />);
  }
  return <ContainerTimelineWidgetLoader containerId={parameters.container_id} lanes={lanes} zoomWindow={zoomWindow} renderWidget={renderWidget} />;
};

export default ContainerTimelineWidget;
