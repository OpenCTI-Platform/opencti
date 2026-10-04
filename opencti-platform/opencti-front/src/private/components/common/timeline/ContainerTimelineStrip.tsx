import React, { Suspense, useMemo } from 'react';
import { graphql, PreloadedQuery, useLazyLoadQuery, usePreloadedQuery } from 'react-relay';
import { Link, useNavigate } from 'react-router';
import { useIntl } from 'react-intl';
import { useTheme } from '@mui/material/styles';
import Skeleton from '@mui/material/Skeleton';
import { AddOutlined } from '@mui/icons-material';
import { Text } from '@filigran/design-system';
import Button from '@common/button/Button';
import Card from '../../../../components/common/card/Card';
import { useFormatter } from '../../../../components/i18n';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import ContainerTimelineAnchors from './ContainerTimelineAnchors';
import ContainerTimelineLanes, { type TimelineChartAnchors } from './ContainerTimelineLanes';
import type { ContainerTimelineStripQuery } from './__generated__/ContainerTimelineStripQuery.graphql';
import type { ContainerTimelineStripEventsQuery, TimelineLane as GqlTimelineLane } from './__generated__/ContainerTimelineStripEventsQuery.graphql';
import {
  computeTimelineExtent,
  computeVisibleDomain,
  effectiveLanes,
  TIMELINE_ADD_MILESTONE_PARAM,
  TIMELINE_ANCHOR_KEYS,
  TIMELINE_LANES,
  type TimelineGrouping,
  toTime,
} from './timelineUtils';
import useTimelineColors from './useTimelineColors';

const STRIP_EVENTS = 300;
// Height of the miniature of the lanes while the events load (the axis and two lanes)
const LANES_PLACEHOLDER_HEIGHT = 86;

export const containerTimelineStripQuery = graphql`
  query ContainerTimelineStripQuery($id: String!) {
    containerTimelineSummary(id: $id) {
      total
      first_event_time
      last_event_time
      can_edit
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
  const navigate = useNavigate();
  const apiLanes = effectiveLanes([], enabledLanes);
  const { containerTimeline } = useLazyLoadQuery<ContainerTimelineStripEventsQuery>(
    containerTimelineStripEventsQuery,
    { id: containerId, lanes: apiLanes as GqlTimelineLane[] | null, count: STRIP_EVENTS },
  );
  // The latest events in chronological order, drawn over the whole span of the timeline
  const events = useMemo(() => (containerTimeline?.edges ?? []).map((edge) => edge.node).reverse(), [containerTimeline]);
  const lanes = TIMELINE_LANES.filter((lane) => (enabledLanes.length > 0 ? enabledLanes : TIMELINE_LANES).includes(lane) && events.some((e) => e.lane === lane));
  const extent = computeTimelineExtent(events, boundaries);
  return (
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
  );
};

/** Count and span of the timeline on one line: "6 events - Feb 1 to Feb 6, 2026". */
const useStripSummary = () => {
  const { t_i18n } = useFormatter();
  const intl = useIntl();
  return (total: number, first: string | null | undefined, last: string | null | undefined) => {
    const start = toTime(first);
    const end = toTime(last) ?? start;
    if (start === null || end === null) {
      return t_i18n('{count, plural, one {# event} other {# events}}', { values: { count: total } });
    }
    const startDate = new Date(start);
    const endDate = new Date(end);
    const longDate = (date: Date) => intl.formatDate(date, { year: 'numeric', month: 'short', day: 'numeric' });
    if (startDate.toDateString() === endDate.toDateString()) {
      return t_i18n('{count, plural, one {# event} other {# events}} - {date}', { values: { count: total, date: longDate(startDate) } });
    }
    const sameYear = startDate.getFullYear() === endDate.getFullYear();
    const from = sameYear ? intl.formatDate(startDate, { month: 'short', day: 'numeric' }) : longDate(startDate);
    return t_i18n('{count, plural, one {# event} other {# events}} - {from} to {to}', { values: { count: total, from, to: longDate(endDate) } });
  };
};

interface ContainerTimelineStripContentProps {
  queryRef: PreloadedQuery<ContainerTimelineStripQuery>;
  containerId: string;
  timelinePath: string;
}

const ContainerTimelineStripContent = ({ queryRef, containerId, timelinePath }: ContainerTimelineStripContentProps) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme();
  const colors = useTimelineColors();
  const navigate = useNavigate();
  const summarize = useStripSummary();
  const { containerTimelineSummary: summary } = usePreloadedQuery<ContainerTimelineStripQuery>(containerTimelineStripQuery, queryRef);
  const total = summary?.total ?? 0;
  const boundaries = [...TIMELINE_ANCHOR_KEYS.map((key) => summary?.anchors?.[key]), summary?.first_event_time, summary?.last_event_time];
  return (
    <div data-testid="timeline-strip" style={{ display: 'flex', flexDirection: 'column', gap: theme.spacing(1.5), height: '100%' }}>
      {total > 0 ? (
        <>
          <Text variant="content-caption" as="div" style={{ color: colors.textSecondary }} data-testid="timeline-strip-summary">
            {summarize(total, summary?.first_event_time, summary?.last_event_time)}
          </Text>
          <Suspense fallback={<Skeleton variant="rounded" height={LANES_PLACEHOLDER_HEIGHT} />}>
            <ContainerTimelineStripLanes
              containerId={containerId}
              enabledLanes={summary?.settings.enabled_lanes ?? []}
              total={total}
              boundaries={boundaries}
              anchors={summary?.anchors}
              grouping={(summary?.settings.default_grouping ?? 'day') as TimelineGrouping}
              timelinePath={timelinePath}
            />
          </Suspense>
          <ContainerTimelineAnchors anchors={summary?.anchors} dense={true} />
        </>
      ) : (
        <div role="status" data-testid="timeline-strip-empty" style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-start', gap: theme.spacing(1.5) }}>
          <Text variant="content-base" as="div">
            {t_i18n('The timeline fills itself from the knowledge of the case and the milestones you add.')}
          </Text>
          {summary?.can_edit && (
            <Button
              variant="secondary"
              size="small"
              startIcon={<AddOutlined fontSize="small" />}
              onClick={() => navigate(`${timelinePath}?${TIMELINE_ADD_MILESTONE_PARAM}=true`)}
              data-testid="timeline-strip-add-milestone"
            >
              {t_i18n('Add a milestone')}
            </Button>
          )}
        </div>
      )}
      <div style={{ marginTop: 'auto' }}>
        <Link to={timelinePath}>{t_i18n('Open the timeline')}</Link>
      </div>
    </div>
  );
};

/** Placeholder in the shape of the card: summary line, miniature of the lanes, anchor rows and footer link. */
const ContainerTimelineStripSkeleton = () => {
  const { t_i18n } = useFormatter();
  const theme = useTheme();
  return (
    <div role="progressbar" aria-label={t_i18n('Loading the timeline')} style={{ display: 'flex', flexDirection: 'column', gap: theme.spacing(1.5) }}>
      <Skeleton variant="text" width="45%" />
      <Skeleton variant="rounded" height={LANES_PLACEHOLDER_HEIGHT} />
      <div style={{ display: 'flex', flexDirection: 'column', gap: theme.spacing(0.5) }}>
        {TIMELINE_ANCHOR_KEYS.map((key) => <Skeleton key={key} variant="text" />)}
      </div>
      <Skeleton variant="text" width={120} />
    </div>
  );
};

interface ContainerTimelineStripProps {
  containerId: string;
  basePath: string;
}

/** Timeline widget of the overview of incidents and cases: a half-width card like the other overview widgets. */
const ContainerTimelineStrip = ({ containerId, basePath }: ContainerTimelineStripProps) => {
  const { t_i18n } = useFormatter();
  const queryRef = useQueryLoading<ContainerTimelineStripQuery>(containerTimelineStripQuery, { id: containerId });
  const timelinePath = `${basePath}/timeline`;
  return (
    <Card title={t_i18n('Timeline')}>
      {queryRef ? (
        <Suspense fallback={<ContainerTimelineStripSkeleton />}>
          <ContainerTimelineStripContent queryRef={queryRef} containerId={containerId} timelinePath={timelinePath} />
        </Suspense>
      ) : (
        <ContainerTimelineStripSkeleton />
      )}
    </Card>
  );
};

export default ContainerTimelineStrip;
