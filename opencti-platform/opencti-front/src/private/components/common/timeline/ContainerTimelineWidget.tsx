import React, { CSSProperties, ReactNode, Suspense, useMemo } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { useNavigate } from 'react-router';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { useFormatter } from '../../../../components/i18n';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { resolveLink } from '../../../../utils/Entity';
import ContainerTimelineLanes from './ContainerTimelineLanes';
import type { ContainerTimelineWidgetQuery, TimelineLane as GqlTimelineLane } from './__generated__/ContainerTimelineWidgetQuery.graphql';
import {
  computeTimelineExtent,
  computeVisibleDomain,
  TIMELINE_ANCHOR_KEYS,
  TIMELINE_LANES,
  TIMELINE_ZOOM_WINDOWS,
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
  query ContainerTimelineWidgetQuery($id: String!, $lanes: [TimelineLane!], $count: Int!) {
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
        default_grouping
      }
    }
    containerTimeline(id: $id, lanes: $lanes, first: $count) {
      edges {
        node {
          id
          event_time
          event_end_time
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

interface ContainerTimelineWidgetContentProps {
  queryRef: PreloadedQuery<ContainerTimelineWidgetQuery>;
  lanes: readonly TimelineLane[];
  zoomWindow: TimelineZoomWindow;
}

const ContainerTimelineWidgetContent = ({ queryRef, lanes, zoomWindow }: ContainerTimelineWidgetContentProps) => {
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const { stixDomainObject: container, containerTimelineSummary: summary, containerTimeline } = usePreloadedQuery<ContainerTimelineWidgetQuery>(
    containerTimelineWidgetQuery,
    queryRef,
  );
  const events = useMemo(() => (containerTimeline?.edges ?? []).map((edge) => edge.node), [containerTimeline]);
  if (!container || !summary) {
    return <WidgetNoData message={t_i18n('The selected incident or case is not available')} />;
  }
  if (events.length === 0) {
    return <WidgetNoData />;
  }
  const enabled = TIMELINE_LANES.filter((lane) => summary.settings.enabled_lanes.includes(lane));
  const shownLanes = (lanes.length > 0 ? lanes : enabled).filter((lane) => events.some((e) => e.lane === lane));
  const extent = computeTimelineExtent(events, TIMELINE_ANCHOR_KEYS.map((key) => summary.anchors?.[key]));
  const timelinePath = `${resolveLink(container.entity_type)}/${container.id}/timeline`;
  return (
    <ContainerTimelineLanes
      events={events}
      lanes={shownLanes}
      domain={computeVisibleDomain(extent, zoomWindow)}
      grouping={(summary.settings.default_grouping ?? 'day') as 'hour' | 'day' | 'week'}
      anchors={summary.anchors}
      onSelect={(eventId) => navigate(`${timelinePath}?event=${encodeURIComponent(eventId)}`)}
      ariaLabel={t_i18n('Timeline of {name}', { values: { name: container.representative.main } })}
    />
  );
};

interface ContainerTimelineWidgetProps {
  parameters?: ContainerTimelineWidgetParameters | null;
  popover?: ReactNode;
  height?: CSSProperties['height'];
  variant?: string;
}

const ContainerTimelineWidgetLoader = ({ containerId, lanes, zoomWindow }: { containerId: string; lanes: readonly TimelineLane[]; zoomWindow: TimelineZoomWindow }) => {
  const queryRef = useQueryLoading<ContainerTimelineWidgetQuery>(
    containerTimelineWidgetQuery,
    { id: containerId, lanes: lanes.length > 0 ? lanes as GqlTimelineLane[] : null, count: WIDGET_EVENTS },
  );
  if (!queryRef) return <Loader variant={LoaderVariant.inElement} />;
  return (
    <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
      <ContainerTimelineWidgetContent queryRef={queryRef} lanes={lanes} zoomWindow={zoomWindow} />
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
  return (
    <WidgetContainer height={height} variant={variant} title={parameters?.title || t_i18n('Incident and case timeline')} action={popover}>
      {parameters?.container_id
        ? <ContainerTimelineWidgetLoader containerId={parameters.container_id} lanes={lanes} zoomWindow={zoomWindow} />
        : <WidgetNoData message={t_i18n('Select an incident or a case in the widget parameters')} />}
    </WidgetContainer>
  );
};

export default ContainerTimelineWidget;
