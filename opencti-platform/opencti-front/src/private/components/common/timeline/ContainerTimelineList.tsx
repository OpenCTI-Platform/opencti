import React, { KeyboardEvent, useMemo, useRef, useState } from 'react';
import { Chip, Text } from '@filigran/design-system';
import { PushPinOutlined, VisibilityOffOutlined } from '@mui/icons-material';
import { useTheme } from '@mui/material/styles';
import { useIntl } from 'react-intl';
import { useFormatter } from '../../../../components/i18n';
import useTimelineColors from './useTimelineColors';
import type { TimelineChartEvent } from './ContainerTimelineLanes';
import TimelineSourceStateChip from './TimelineSourceStateChip';
import {
  groupEventsByBucket,
  TIMELINE_KIND_LABELS,
  TIMELINE_LANE_LABELS,
  TIMELINE_PRECISION_LABELS,
  type TimelineGrouping,
  type TimelineLane,
  type TimelinePrecision,
} from './timelineUtils';

export interface TimelineListEvent extends TimelineChartEvent {
  element_name?: string | null;
  // The user can pin, hide and annotate this event (container rights and confidence of the event)
  annotatable?: boolean;
}

interface ContainerTimelineListProps {
  events: readonly TimelineListEvent[];
  grouping: TimelineGrouping;
  selectedId?: string | null;
  canEdit: boolean;
  onSelect: (eventId: string) => void;
  onTogglePin?: (event: TimelineListEvent) => void;
  onToggleHide?: (event: TimelineListEvent) => void;
}

/**
 * Accessible vertical view of the timeline: events grouped by hour, day or week under headings,
 * one focusable item at a time (roving tab index) navigated with the arrow keys.
 */
const ContainerTimelineList = ({ events, grouping, selectedId, canEdit, onSelect, onTogglePin, onToggleHide }: ContainerTimelineListProps) => {
  const { t_i18n, fldt } = useFormatter();
  const intl = useIntl();
  const theme = useTheme();
  const colors = useTimelineColors();
  const buckets = useMemo(() => groupEventsByBucket([...events], grouping), [events, grouping]);
  const ordered = useMemo(() => buckets.flatMap((bucket) => bucket.events), [buckets]);
  const [focusedId, setFocusedId] = useState<string | null>(selectedId ?? null);
  const itemRefs = useRef(new Map<string, HTMLDivElement>());
  const activeId = focusedId && ordered.some((e) => e.id === focusedId) ? focusedId : ordered[0]?.id;

  const focusItem = (id: string | undefined) => {
    if (!id) return;
    setFocusedId(id);
    itemRefs.current.get(id)?.focus();
  };

  const onItemKeyDown = (keyEvent: KeyboardEvent<HTMLDivElement>, event: TimelineListEvent) => {
    const index = ordered.findIndex((e) => e.id === event.id);
    const actions: Record<string, () => void> = {
      ArrowDown: () => focusItem(ordered[Math.min(index + 1, ordered.length - 1)]?.id),
      ArrowUp: () => focusItem(ordered[Math.max(index - 1, 0)]?.id),
      Home: () => focusItem(ordered[0]?.id),
      End: () => focusItem(ordered[ordered.length - 1]?.id),
      Enter: () => onSelect(event.id),
      ' ': () => onSelect(event.id),
    };
    const canContribute = canEdit && event.annotatable !== false;
    if (canContribute && onTogglePin) actions.p = () => onTogglePin(event);
    if (canContribute && onToggleHide) actions.h = () => onToggleHide(event);
    const action = actions[keyEvent.key];
    if (action) {
      keyEvent.preventDefault();
      action();
    }
  };

  const bucketTitle = (start: number, end: number) => {
    if (grouping === 'hour') return `${intl.formatDate(start, { dateStyle: 'full' })} ${intl.formatTime(start, { hour: '2-digit', minute: '2-digit' })}`;
    if (grouping === 'day') return intl.formatDate(start, { dateStyle: 'full' });
    return t_i18n('Week of {from} to {to}', { values: { from: intl.formatDate(start, { dateStyle: 'medium' }), to: intl.formatDate(end - 1, { dateStyle: 'medium' }) } });
  };

  if (ordered.length === 0) {
    return (
      <div role="status" style={{ padding: theme.spacing(2) }}>
        <Text variant="content-base" style={{ color: colors.textSecondary }}>{t_i18n('No event matches the current filters')}</Text>
      </div>
    );
  }

  return (
    <div
      role="list"
      aria-label={t_i18n('Timeline events')}
      aria-describedby="timeline-list-help"
      data-testid="timeline-list"
    >
      <Text variant="content-caption" as="p" id="timeline-list-help" style={{ color: colors.textSecondary, margin: theme.spacing(0, 0, 1, 0) }}>
        {canEdit
          ? t_i18n('Use the up and down arrows to move between events, Enter to open, P to pin and H to hide')
          : t_i18n('Use the up and down arrows to move between events and Enter to open')}
      </Text>
      {buckets.map((bucket) => (
        <section key={bucket.key} aria-label={bucketTitle(bucket.start, bucket.end)} role="listitem">
          <Text variant="content-compact-bold" as="h3" style={{ margin: theme.spacing(2, 0, 0.75, 0), color: colors.textSecondary }}>
            {bucketTitle(bucket.start, bucket.end)}
          </Text>
          <div role="list">
            {bucket.events.map((event) => {
              const lane = event.lane as TimelineLane;
              const selected = event.id === selectedId;
              return (
                <div key={event.id} role="listitem">
                  {/* The row opens the event: button semantics on the row content, list semantics on its wrapper */}
                  <div
                    role="button"
                    ref={(node) => {
                      if (node) itemRefs.current.set(event.id, node);
                      else itemRefs.current.delete(event.id);
                    }}
                    tabIndex={event.id === activeId ? 0 : -1}
                    aria-current={selected ? 'true' : undefined}
                    aria-label={`${event.title}, ${fldt(event.event_time)}, ${t_i18n(TIMELINE_LANE_LABELS[lane] ?? lane)}`}
                    data-testid={`timeline-list-event-${event.id}`}
                    onFocus={() => setFocusedId(event.id)}
                    onKeyDown={(keyEvent) => onItemKeyDown(keyEvent, event)}
                    onClick={() => onSelect(event.id)}
                    style={{
                      display: 'flex',
                      alignItems: 'flex-start',
                      gap: theme.spacing(1.25),
                      padding: theme.spacing(1, 1.25),
                      marginBottom: theme.spacing(0.5),
                      borderLeft: `4px solid ${colors.lanes[lane] ?? colors.textSecondary}`,
                      borderRadius: theme.shape.borderRadius,
                      background: selected ? colors.laneBackground : 'transparent',
                      outlineColor: colors.focus,
                      cursor: 'pointer',
                      opacity: event.hidden ? 0.55 : 1,
                    }}
                  >
                    <Text variant="content-caption" as="div" style={{ minWidth: 150, color: colors.textSecondary }}>
                      <div>{fldt(event.event_time)}</div>
                      {event.event_end_time && <div>{`\u2192 ${fldt(event.event_end_time)}`}</div>}
                      {!event.event_end_time && event.open_ended && <div>{`\u2192 ${t_i18n('Still open')}`}</div>}
                    </Text>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(0.75), flexWrap: 'wrap' }}>
                        <Text variant="content-base-bold" as="span">{event.title}</Text>
                        {event.pinned && <PushPinOutlined fontSize="inherit" titleAccess={t_i18n('Pinned')} />}
                        {event.hidden && <VisibilityOffOutlined fontSize="inherit" titleAccess={t_i18n('Hidden')} />}
                      </div>
                      <div style={{ display: 'flex', gap: theme.spacing(0.75), marginTop: theme.spacing(0.5), flexWrap: 'wrap' }}>
                        <Chip label={t_i18n(TIMELINE_LANE_LABELS[lane] ?? lane)} color={colors.lanes[lane]} />
                        <Chip label={t_i18n(TIMELINE_KIND_LABELS[event.kind] ?? event.kind)} />
                        <TimelineSourceStateChip state={event.source_state} />
                        {event.precision !== 'exact' && (
                          <Chip label={t_i18n(TIMELINE_PRECISION_LABELS[event.precision as TimelinePrecision] ?? event.precision)} severity="medium" />
                        )}
                        {event.source === 'manual' && <Chip label={t_i18n('Milestone')} severity="info" />}
                      </div>
                      {event.element_name && (
                        <Text variant="content-caption" as="div" style={{ marginTop: theme.spacing(0.5), color: colors.textSecondary }}>{event.element_name}</Text>
                      )}
                      {event.annotation && (
                        <Text variant="content-caption" as="div" style={{ marginTop: theme.spacing(0.5), fontStyle: 'italic' }}>{event.annotation}</Text>
                      )}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </section>
      ))}
    </div>
  );
};

export default ContainerTimelineList;
