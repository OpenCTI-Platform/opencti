import React, { Suspense, useMemo } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { Link, useNavigate } from 'react-router';
import Card from '../../../../components/common/card/Card';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { useFormatter } from '../../../../components/i18n';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import ContainerTimelineAnchors from './ContainerTimelineAnchors';
import ContainerTimelineLanes from './ContainerTimelineLanes';
import type { ContainerTimelineStripQuery } from './__generated__/ContainerTimelineStripQuery.graphql';
import { computeTimelineExtent, computeVisibleDomain, TIMELINE_ANCHOR_KEYS, TIMELINE_LANES } from './timelineUtils';

const STRIP_EVENTS = 300;

export const containerTimelineStripQuery = graphql`
  query ContainerTimelineStripQuery($id: String!, $count: Int!) {
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
    containerTimeline(id: $id, first: $count, orderMode: desc) {
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

interface ContainerTimelineStripContentProps {
  queryRef: PreloadedQuery<ContainerTimelineStripQuery>;
  timelinePath: string;
}

const ContainerTimelineStripContent = ({ queryRef, timelinePath }: ContainerTimelineStripContentProps) => {
  const { t_i18n, n } = useFormatter();
  const navigate = useNavigate();
  const { containerTimelineSummary: summary, containerTimeline } = usePreloadedQuery<ContainerTimelineStripQuery>(containerTimelineStripQuery, queryRef);
  // The latest events in chronological order, drawn over the whole span of the timeline
  const events = useMemo(() => (containerTimeline?.edges ?? []).map((edge) => edge.node).reverse(), [containerTimeline]);
  const lanes = TIMELINE_LANES.filter((lane) => (summary?.settings.enabled_lanes ?? TIMELINE_LANES).includes(lane) && events.some((e) => e.lane === lane));
  const extent = computeTimelineExtent(events, [
    ...TIMELINE_ANCHOR_KEYS.map((key) => summary?.anchors?.[key]),
    summary?.first_event_time,
    summary?.last_event_time,
  ]);
  return (
    <div data-testid="timeline-strip">
      <ContainerTimelineAnchors anchors={summary?.anchors} dense={true} />
      {events.length > 0 ? (
        <div style={{ marginTop: 8 }}>
          <ContainerTimelineLanes
            events={events}
            lanes={lanes}
            domain={computeVisibleDomain(extent, 'fit')}
            grouping={(summary?.settings.default_grouping ?? 'day') as 'hour' | 'day' | 'week'}
            anchors={summary?.anchors}
            compact={true}
            onSelect={(eventId) => navigate(`${timelinePath}?event=${encodeURIComponent(eventId)}`)}
            ariaLabel={t_i18n('Overview of the timeline, {count} events', { values: { count: summary?.total ?? events.length } })}
          />
        </div>
      ) : (
        <div style={{ marginTop: 8, fontSize: 12 }}>{t_i18n('This timeline has no event yet')}</div>
      )}
      <div style={{ marginTop: 6, fontSize: 12 }}>
        {t_i18n('{count} events', { values: { count: n(summary?.total ?? 0) } })}
      </div>
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
  const queryRef = useQueryLoading<ContainerTimelineStripQuery>(containerTimelineStripQuery, { id: containerId, count: STRIP_EVENTS });
  const timelinePath = `${basePath}/timeline`;
  return (
    <Card title={t_i18n('Timeline')} action={<Link to={timelinePath}>{t_i18n('Open the timeline')}</Link>}>
      {queryRef ? (
        <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
          <ContainerTimelineStripContent queryRef={queryRef} timelinePath={timelinePath} />
        </Suspense>
      ) : (
        <Loader variant={LoaderVariant.inElement} />
      )}
    </Card>
  );
};

export default ContainerTimelineStrip;
