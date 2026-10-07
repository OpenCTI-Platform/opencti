import React, { Suspense, useMemo } from 'react';
import { graphql, PreloadedQuery, useLazyLoadQuery, usePreloadedQuery } from 'react-relay';
import { Link, useNavigate } from 'react-router';
import { useIntl } from 'react-intl';
import { useTheme } from '@mui/material/styles';
import Skeleton from '@mui/material/Skeleton';
import { AddOutlined, SettingsOutlined } from '@mui/icons-material';
import { Text } from '@filigran/design-system';
import Button from '@common/button/Button';
import Card from '../../../../components/common/card/Card';
import { useFormatter } from '../../../../components/i18n';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import ContainerTimelineAnchors from './ContainerTimelineAnchors';
import ContainerTimelineLanes, { type TimelineChartAnchors } from './ContainerTimelineLanes';
import type { ContainerTimelineStripQuery } from './__generated__/ContainerTimelineStripQuery.graphql';
import type {
  ContainerTimelineStripEventsQuery,
  TimelineEventKind as GqlTimelineEventKind,
  TimelineLane as GqlTimelineLane,
} from './__generated__/ContainerTimelineStripEventsQuery.graphql';
import {
  computeTimelineExtent,
  computeVisibleDomain,
  effectiveKinds,
  effectiveLanes,
  TIMELINE_ADD_MILESTONE_PARAM,
  TIMELINE_ANCHOR_KEYS,
  TIMELINE_LANES,
  TIMELINE_MILESTONE_DEFAULT_KIND,
  TIMELINE_MILESTONE_DEFAULT_LANE,
  TIMELINE_OPEN_SETTINGS_PARAM,
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
        hidden_kinds
        default_grouping
      }
    }
  }
`;

// The lanes disabled and the kinds hidden in the timeline settings are left out before the limit, so they never displace
// the others; the count and the span of the card come from the summary of the same lanes and kinds, over every event
const containerTimelineStripEventsQuery = graphql`
  query ContainerTimelineStripEventsQuery($id: String!, $lanes: [TimelineLane!], $kinds: [TimelineEventKind!], $count: Int!) {
    shown: containerTimelineSummary(id: $id, lanes: $lanes, kinds: $kinds) {
      total
      first_event_time
      last_event_time
    }
    containerTimeline(id: $id, lanes: $lanes, kinds: $kinds, first: $count, orderMode: desc) {
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

interface ContainerTimelineStripEmptyProps {
  message: string;
  canEdit: boolean;
  timelinePath: string;
  // The settings hide every event: the next step is the settings panel, a milestone only when the settings would show it
  hiddenBySettings?: boolean;
  milestoneShown?: boolean;
}

/** What the card shows when it has no event to draw, with the next step. */
const ContainerTimelineStripEmpty = ({ message, canEdit, timelinePath, hiddenBySettings = false, milestoneShown = true }: ContainerTimelineStripEmptyProps) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme();
  const navigate = useNavigate();
  const addMilestone = (
    <Button
      variant="secondary"
      size="small"
      startIcon={<AddOutlined fontSize="small" />}
      onClick={() => navigate(`${timelinePath}?${TIMELINE_ADD_MILESTONE_PARAM}=true`)}
      data-testid="timeline-strip-add-milestone"
    >
      {t_i18n('Add a milestone')}
    </Button>
  );
  return (
    <div role="status" data-testid="timeline-strip-empty" style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-start', gap: theme.spacing(1.5) }}>
      <Text variant="content-base" as="div">{message}</Text>
      {canEdit && (hiddenBySettings ? (
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: theme.spacing(1) }}>
          <Button
            size="small"
            startIcon={<SettingsOutlined fontSize="small" />}
            onClick={() => navigate(`${timelinePath}?${TIMELINE_OPEN_SETTINGS_PARAM}=true`)}
            data-testid="timeline-strip-open-settings"
          >
            {t_i18n('Timeline settings')}
          </Button>
          {milestoneShown && addMilestone}
        </div>
      ) : addMilestone)}
    </div>
  );
};

interface ContainerTimelineStripEventsProps {
  containerId: string;
  enabledLanes: readonly string[];
  hiddenKinds: readonly string[];
  anchors: TimelineChartAnchors;
  grouping: TimelineGrouping;
  timelinePath: string;
  canEdit: boolean;
}

/** Summary line and miniature of the lanes, both from the events the timeline settings show. */
const ContainerTimelineStripEvents = ({ containerId, enabledLanes, hiddenKinds, anchors, grouping, timelinePath, canEdit }: ContainerTimelineStripEventsProps) => {
  const { t_i18n } = useFormatter();
  const colors = useTimelineColors();
  const navigate = useNavigate();
  const summarize = useStripSummary();
  const apiLanes = effectiveLanes([], enabledLanes);
  const { containerTimeline, shown } = useLazyLoadQuery<ContainerTimelineStripEventsQuery>(
    containerTimelineStripEventsQuery,
    {
      id: containerId,
      lanes: apiLanes as GqlTimelineLane[] | null,
      kinds: effectiveKinds([], hiddenKinds) as GqlTimelineEventKind[] | null,
      count: STRIP_EVENTS,
    },
  );
  // The latest events in chronological order, drawn over the whole span of the timeline
  const events = useMemo(() => (containerTimeline?.edges ?? []).map((edge) => edge.node).reverse(), [containerTimeline]);
  const total = shown?.total ?? events.length;
  const lanes = TIMELINE_LANES.filter((lane) => (enabledLanes.length > 0 ? enabledLanes : TIMELINE_LANES).includes(lane) && events.some((e) => e.lane === lane));
  // The span covers every shown event, also those older than the latest ones drawn here
  const extent = computeTimelineExtent(events, [...TIMELINE_ANCHOR_KEYS.map((key) => anchors?.[key]), shown?.first_event_time, shown?.last_event_time]);
  if (total === 0) {
    return (
      <ContainerTimelineStripEmpty
        message={canEdit
          ? t_i18n('Every event of the case is in a lane or a kind the timeline settings hide. Change the settings from the Timeline tab.')
          : t_i18n('Every event of the case is in a lane or a kind the timeline settings hide.')}
        canEdit={canEdit}
        timelinePath={timelinePath}
        hiddenBySettings={true}
        milestoneShown={(enabledLanes.length === 0 || enabledLanes.includes(TIMELINE_MILESTONE_DEFAULT_LANE)) && !hiddenKinds.includes(TIMELINE_MILESTONE_DEFAULT_KIND)}
      />
    );
  }
  return (
    <>
      <Text variant="content-caption" as="div" style={{ color: colors.textSecondary }} data-testid="timeline-strip-summary">
        {summarize(total, shown?.first_event_time, shown?.last_event_time)}
      </Text>
      {events.length > 0 && (
        <ContainerTimelineLanes
          events={events}
          lanes={lanes}
          domain={computeVisibleDomain(extent, 'fit')}
          grouping={grouping}
          anchors={anchors}
          compact={true}
          onSelect={(eventId) => navigate(`${timelinePath}?event=${encodeURIComponent(eventId)}`)}
          ariaLabel={t_i18n('Overview of the timeline, {count, plural, one {# event} other {# events}}', { values: { count: total } })}
        />
      )}
    </>
  );
};

/** Placeholder of the summary line and of the miniature of the lanes while the events load. */
const ContainerTimelineStripEventsSkeleton = () => (
  <>
    <Skeleton variant="text" width="45%" />
    <Skeleton variant="rounded" height={LANES_PLACEHOLDER_HEIGHT} />
  </>
);

interface ContainerTimelineStripContentProps {
  queryRef: PreloadedQuery<ContainerTimelineStripQuery>;
  containerId: string;
  timelinePath: string;
}

const ContainerTimelineStripContent = ({ queryRef, containerId, timelinePath }: ContainerTimelineStripContentProps) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme();
  const { containerTimelineSummary: summary } = usePreloadedQuery<ContainerTimelineStripQuery>(containerTimelineStripQuery, queryRef);
  const canEdit = !!summary?.can_edit;
  return (
    <div data-testid="timeline-strip" style={{ display: 'flex', flexDirection: 'column', gap: theme.spacing(1.5), height: '100%' }}>
      {(summary?.total ?? 0) > 0 ? (
        <>
          <Suspense fallback={<ContainerTimelineStripEventsSkeleton />}>
            <ContainerTimelineStripEvents
              containerId={containerId}
              enabledLanes={summary?.settings.enabled_lanes ?? []}
              hiddenKinds={summary?.settings.hidden_kinds ?? []}
              anchors={summary?.anchors}
              grouping={(summary?.settings.default_grouping ?? 'day') as TimelineGrouping}
              timelinePath={timelinePath}
              canEdit={canEdit}
            />
          </Suspense>
          <ContainerTimelineAnchors anchors={summary?.anchors} dense={true} />
        </>
      ) : (
        <ContainerTimelineStripEmpty
          message={t_i18n('The timeline fills itself from the knowledge of the case and the milestones you add.')}
          canEdit={canEdit}
          timelinePath={timelinePath}
        />
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
