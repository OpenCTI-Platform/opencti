import React, { Suspense, useMemo } from 'react';
import { graphql, PreloadedQuery, useLazyLoadQuery, usePreloadedQuery } from 'react-relay';
import { Link, useNavigate } from 'react-router';
import { useTheme } from '@mui/material/styles';
import { Text } from '@filigran/design-system';
import Card from '../../../../components/common/card/Card';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { useFormatter } from '../../../../components/i18n';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import ContainerTimelineAnchors from './ContainerTimelineAnchors';
import ContainerTimelineLanes, { type TimelineChartAnchors } from './ContainerTimelineLanes';
import type { ContainerTimelineStripQuery } from './__generated__/ContainerTimelineStripQuery.graphql';
import type { ContainerTimelineStripEventsQuery, TimelineLane as GqlTimelineLane } from './__generated__/ContainerTimelineStripEventsQuery.graphql';
import { computeTimelineExtent, computeVisibleDomain, effectiveLanes, TIMELINE_ANCHOR_KEYS, TIMELINE_LANES, type TimelineGrouping } from './timelineUtils';

const STRIP_EVENTS = 300;

export const containerTimelineStripQuery = graphql`
  query ContainerTimelineStripQuery($id: String!) {
    containerTimelineSummary(id: $id) {
      total
      first_event_time
      last_event_time
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
  }
`;

// The lanes disabled in the timeline settings are left out before the limit, so they never displace the others
const containerTimelineStripEventsQuery = graphql`
  query ContainerTimelineStripEventsQuery($id: String!, $lanes: [TimelineLane!], $count: Int!) {
    containerTimeline(id: $id, lanes: $lanes, first: $count, orderMode: desc) {
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

interface ContainerTimelineStripLanesProps {
  containerId: string;
  enabledLanes: readonly string[];
  total: number;
  boundaries: (string | null | undefined)[];
  anchors: TimelineChartAnchors;
  grouping: TimelineGrouping;
  timelinePath: string;
}

const ContainerTimelineStripLanes = ({ containerId, enabledLanes, total, boundaries, anchors, grouping, timelinePath }: ContainerTimelineStripLanesProps) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme();
  const navigate = useNavigate();
  const apiLanes = effectiveLanes([], enabledLanes);
  const { containerTimeline } = useLazyLoadQuery<ContainerTimelineStripEventsQuery>(
    containerTimelineStripEventsQuery,
    { id: containerId, lanes: apiLanes as GqlTimelineLane[] | null, count: STRIP_EVENTS },
  );
  // The latest events in chronological order, drawn over the whole span of the timeline
  const events = useMemo(() => (containerTimeline?.edges ?? []).map((edge) => edge.node).reverse(), [containerTimeline]);
  const lanes = TIMELINE_LANES.filter((lane) => (enabledLanes.length > 0 ? enabledLanes : TIMELINE_LANES).includes(lane) && events.some((e) => e.lane === lane));
  if (events.length === 0) {
    return <Text variant="content-caption" as="div" style={{ marginTop: theme.spacing(1) }}>{t_i18n('This timeline has no event yet')}</Text>;
  }
  const extent = computeTimelineExtent(events, boundaries);
  return (
    <div style={{ marginTop: theme.spacing(1) }}>
      <ContainerTimelineLanes
        events={events}
        lanes={lanes}
        domain={computeVisibleDomain(extent, 'fit')}
        grouping={grouping}
        anchors={anchors}
        compact={true}
        onSelect={(eventId) => navigate(`${timelinePath}?event=${encodeURIComponent(eventId)}`)}
        ariaLabel={t_i18n('Overview of the timeline, {count} events', { values: { count: total || events.length } })}
      />
    </div>
  );
};

interface ContainerTimelineStripContentProps {
  queryRef: PreloadedQuery<ContainerTimelineStripQuery>;
  containerId: string;
  timelinePath: string;
}

const ContainerTimelineStripContent = ({ queryRef, containerId, timelinePath }: ContainerTimelineStripContentProps) => {
  const { t_i18n, n } = useFormatter();
  const theme = useTheme();
  const { containerTimelineSummary: summary } = usePreloadedQuery<ContainerTimelineStripQuery>(containerTimelineStripQuery, queryRef);
  const boundaries = [...TIMELINE_ANCHOR_KEYS.map((key) => summary?.anchors?.[key]), summary?.first_event_time, summary?.last_event_time];
  return (
    <div data-testid="timeline-strip">
      <ContainerTimelineAnchors anchors={summary?.anchors} dense={true} />
      {(summary?.total ?? 0) > 0 ? (
        <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
          <ContainerTimelineStripLanes
            containerId={containerId}
            enabledLanes={summary?.settings.enabled_lanes ?? []}
            total={summary?.total ?? 0}
            boundaries={boundaries}
            anchors={summary?.anchors}
            grouping={(summary?.settings.default_grouping ?? 'day') as TimelineGrouping}
            timelinePath={timelinePath}
          />
        </Suspense>
      ) : (
        <Text variant="content-caption" as="div" style={{ marginTop: theme.spacing(1) }}>{t_i18n('This timeline has no event yet')}</Text>
      )}
      <Text variant="content-caption" as="div" style={{ marginTop: theme.spacing(0.75) }}>
        {t_i18n('{count} events', { values: { count: n(summary?.total ?? 0) } })}
      </Text>
    </div>
  );
};

interface ContainerTimelineStripProps {
  containerId: string;
  basePath: string;
}

/** Compact timeline on the overview of incidents and cases: anchors and a miniature of the lanes. */
const ContainerTimelineStrip = ({ containerId, basePath }: ContainerTimelineStripProps) => {
  const { t_i18n } = useFormatter();
  const queryRef = useQueryLoading<ContainerTimelineStripQuery>(containerTimelineStripQuery, { id: containerId });
  const timelinePath = `${basePath}/timeline`;
  return (
    <Card title={t_i18n('Timeline')} action={<Link to={timelinePath}>{t_i18n('Open the timeline')}</Link>}>
      {queryRef ? (
        <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
          <ContainerTimelineStripContent queryRef={queryRef} containerId={containerId} timelinePath={timelinePath} />
        </Suspense>
      ) : (
        <Loader variant={LoaderVariant.inElement} />
      )}
    </Card>
  );
};

export default ContainerTimelineStrip;
