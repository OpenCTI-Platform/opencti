import React, { KeyboardEvent, PointerEvent, Ref, useCallback, useEffect, useId, useMemo, useRef, useState } from 'react';
import { scaleTime } from 'd3-scale';
import { useIntl } from 'react-intl';
import { useTheme } from '@mui/material/styles';
import { Text } from '@filigran/design-system';
import { useFormatter } from '../../../../components/i18n';
import useTimelineColors from './useTimelineColors';
import { resolveTimelineSourceState, type TimelineSourceStateValue } from './timelineSourceStates';
import {
  clusterLaneEvents,
  compactDayTicks,
  groupOverflowItems,
  layoutAnchorLabels,
  layoutLaneRows,
  panDomain,
  TIMELINE_ANCHOR_KEYS,
  TIMELINE_ANCHOR_LABELS,
  TIMELINE_KIND_LABELS,
  TIMELINE_LANE_LABELS,
  type TimelineAnchorKey,
  type TimelineCluster,
  type TimelineDomain,
  type TimelineGrouping,
  type TimelineLane,
  toTime,
  zoomDomain,
} from './timelineUtils';

export interface TimelineChartEvent {
  id: string;
  title: string;
  event_time: string;
  event_end_time?: string | null;
  lane: string;
  kind: string;
  precision: string;
  pinned: boolean;
  hidden: boolean;
  source: string;
  annotation?: string | null;
  source_state?: TimelineSourceStateValue | null;
}

export type TimelineChartAnchors = Partial<Record<TimelineAnchorKey, string | null | undefined>> | null | undefined;

interface ContainerTimelineLanesProps {
  events: readonly TimelineChartEvent[];
  lanes: readonly TimelineLane[];
  domain: TimelineDomain;
  grouping: TimelineGrouping;
  anchors?: TimelineChartAnchors;
  selectedId?: string | null;
  // Overview card mode: narrow lane labels, day ticks, no row stacking beyond 2 rows, no event labels, no zoom
  compact?: boolean;
  onDomainChange?: (domain: TimelineDomain) => void;
  onFit?: () => void;
  onSelect?: (eventId: string) => void;
  onClusterSelect?: (domain: TimelineDomain) => void;
  svgRef?: Ref<SVGSVGElement>;
  ariaLabel: string;
}

const LABEL_WIDTH = 116;
const COMPACT_LABEL_WIDTH = 84;
const COMPACT_LABEL_CHARS = 12;
const COMPACT_MAX_TICKS = 5;
const AXIS_HEIGHT = 30;
const ANCHOR_HEIGHT = 18;
const ROW_HEIGHT = 20;
const LANE_PADDING = 8;
const MAX_ROWS = 8;
const COMPACT_MAX_ROWS = 2;
const POINT_RADIUS = 5;
const MARKER_WIDTH = 14;
const LABEL_CHARS = 26;
const ZOOM_STEP = 0.7;
const PAN_STEP = 0.15;

const truncate = (value: string, max: number) => (value.length > max ? `${value.slice(0, max - 1)}\u2026` : value);

interface HoverState {
  event: TimelineChartEvent;
  x: number;
  y: number;
}

type LaneItem = { type: 'event'; id: string; event: TimelineChartEvent; x1: number; x2: number }
  | { type: 'cluster'; id: string; cluster: TimelineCluster<TimelineChartEvent>; x1: number; x2: number };

const ContainerTimelineLanes = ({
  events,
  lanes,
  domain,
  grouping,
  anchors,
  selectedId,
  compact = false,
  onDomainChange,
  onFit,
  onSelect,
  onClusterSelect,
  svgRef,
  ariaLabel,
}: ContainerTimelineLanesProps) => {
  const { t_i18n, fldt } = useFormatter();
  const theme = useTheme();
  const intl = useIntl();
  const colors = useTimelineColors();
  const clipId = `timeline-plot-${useId().replace(/[^a-zA-Z0-9_-]/g, '')}`;
  const containerRef = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState(960);
  const [hover, setHover] = useState<HoverState | null>(null);
  const hoverState = hover ? resolveTimelineSourceState(hover.event.source_state) : null;
  const dragRef = useRef<{ x: number; domain: TimelineDomain } | null>(null);
  const interactive = !!onDomainChange && !compact;

  useEffect(() => {
    const element = containerRef.current;
    if (!element) return undefined;
    const observer = new ResizeObserver((entries) => {
      const measured = Math.floor(entries[0]?.contentRect.width ?? 0);
      if (measured > 0) setWidth(measured);
    });
    observer.observe(element);
    return () => observer.disconnect();
  }, []);

  const labelWidth = compact ? COMPACT_LABEL_WIDTH : LABEL_WIDTH;
  const plotLeft = labelWidth + 8;
  const plotRight = Math.max(width - 12, plotLeft + 50);
  const plotWidth = plotRight - plotLeft;
  const scale = useMemo(() => scaleTime().domain([new Date(domain[0]), new Date(domain[1])]).range([plotLeft, plotRight]), [domain, plotLeft, plotRight]);

  // Lane items: events and clusters positioned on the x axis, stacked on rows when they overlap
  const laneLayouts = useMemo(() => {
    const maxRows = compact ? COMPACT_MAX_ROWS : MAX_ROWS;
    let y = AXIS_HEIGHT;
    return lanes.map((lane) => {
      const laneEvents = events.filter((event) => event.lane === lane);
      const { singles, clusters } = clusterLaneEvents(laneEvents, grouping);
      const items: LaneItem[] = [];
      singles.forEach((event) => {
        const start = toTime(event.event_time) as number;
        const end = toTime(event.event_end_time);
        const x1 = scale(new Date(start));
        const x2 = end !== null ? Math.max(scale(new Date(end)), x1 + MARKER_WIDTH) : x1 + MARKER_WIDTH;
        const labelled = !compact && (event.pinned || event.source === 'manual');
        if (x2 < plotLeft || x1 > plotRight) return;
        items.push({ type: 'event', id: event.id, event, x1: x1 - POINT_RADIUS, x2: labelled ? x2 + 6 * Math.min(event.title.length, LABEL_CHARS) : x2 });
      });
      clusters.forEach((cluster) => {
        const x = scale(new Date(cluster.start + (cluster.end - cluster.start) / 2));
        if (x < plotLeft || x > plotRight) return;
        items.push({ type: 'cluster', id: cluster.id, cluster, x1: x - 11, x2: x + 11 });
      });
      const { rows, rowCount } = layoutLaneRows(items.map(({ id, x1, x2 }) => ({ id, x1, x2 })));
      const visibleRows = Math.min(rowCount, maxRows);
      const height = LANE_PADDING * 2 + visibleRows * ROW_HEIGHT;
      let drawnItems = items;
      if (rowCount > maxRows) {
        // The last drawn row and the rows beyond it collapse into count bubbles that zoom in on click, never stacked items
        const lastRow = maxRows - 1;
        const isOverflow = (item: LaneItem) => (rows.get(item.id) ?? 0) >= lastRow;
        const groups = groupOverflowItems(items.filter(isOverflow).map((item) => ({
          id: item.id,
          x1: item.x1 - 11,
          x2: item.x2 + 11,
          events: item.type === 'event' ? [item.event] : item.cluster.events,
          item,
        })));
        const collapsed: LaneItem[] = groups.map((group, index) => {
          if (group.length === 1) return group[0].item;
          const groupEvents = group.flatMap((entry) => entry.events);
          const times = groupEvents.flatMap((event) => [toTime(event.event_time), toTime(event.event_end_time)]).filter((t): t is number => t !== null);
          const cluster = { id: `${lane}-overflow-${index}`, lane, start: Math.min(...times), end: Math.max(...times), events: groupEvents };
          const x = scale(new Date(cluster.start + (cluster.end - cluster.start) / 2));
          return { type: 'cluster', id: cluster.id, cluster, x1: x - 11, x2: x + 11 };
        });
        collapsed.forEach((item) => rows.set(item.id, lastRow));
        drawnItems = [...items.filter((item) => !isOverflow(item)), ...collapsed];
      }
      const layout = { lane, y, height, items: drawnItems, rows, maxRows };
      y += height;
      return layout;
    });
  }, [lanes, events, grouping, scale, compact, plotLeft, plotRight]);

  const lanesBottom = laneLayouts.length > 0 ? laneLayouts[laneLayouts.length - 1].y + laneLayouts[laneLayouts.length - 1].height : AXIS_HEIGHT;
  // A half-width card names at most five days, never overlapping; the full views follow the zoom
  const ticks = useMemo(() => (compact ? compactDayTicks(domain, COMPACT_MAX_TICKS) : scale.ticks(Math.max(2, Math.floor(plotWidth / 120)))), [compact, domain, scale, plotWidth]);
  const span = domain[1] - domain[0];
  // The label follows the tick step, so two ticks of the same day never read the same
  const tickStep = ticks.length > 1 ? ticks[1].getTime() - ticks[0].getTime() : span;
  const formatTick = useCallback((tick: Date) => {
    if (compact) return intl.formatDate(tick, { month: 'short', day: 'numeric' });
    const day = 24 * 3600 * 1000;
    if (tickStep < day) {
      return span <= 2 * day
        ? intl.formatTime(tick, { hour: '2-digit', minute: '2-digit' })
        : intl.formatDate(tick, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
    }
    if (tickStep < 28 * day) return intl.formatDate(tick, { month: 'short', day: 'numeric' });
    return intl.formatDate(tick, { year: 'numeric', month: 'short' });
  }, [compact, intl, span, tickStep]);
  // The labels at both ends of a compact axis stay inside the drawing
  const tickAnchor = (x: number) => {
    if (!compact) return 'middle';
    if (x < plotLeft + 24) return 'start';
    return x > plotRight - 24 ? 'end' : 'middle';
  };

  // region interactions
  const zoomAt = useCallback((factor: number, clientX?: number) => {
    if (!onDomainChange) return;
    let focus: number | undefined;
    const rect = containerRef.current?.getBoundingClientRect();
    if (clientX !== undefined && rect) {
      focus = scale.invert(clientX - rect.left).getTime();
    }
    onDomainChange(zoomDomain(domain, factor, focus));
  }, [onDomainChange, scale, domain]);

  useEffect(() => {
    const element = containerRef.current;
    if (!element || !interactive) return undefined;
    // Native listener: React wheel listeners are passive and cannot prevent the page scroll
    const onWheel = (event: WheelEvent) => {
      if (event.ctrlKey || event.metaKey) {
        event.preventDefault();
        zoomAt(event.deltaY > 0 ? 1 / ZOOM_STEP : ZOOM_STEP, event.clientX);
      } else if (event.shiftKey && onDomainChange) {
        event.preventDefault();
        onDomainChange(panDomain(domain, (event.deltaY || event.deltaX) * (span / plotWidth)));
      }
    };
    element.addEventListener('wheel', onWheel, { passive: false });
    return () => element.removeEventListener('wheel', onWheel);
  }, [interactive, zoomAt, onDomainChange, domain, span, plotWidth]);

  const onPointerDown = (event: PointerEvent<SVGRectElement>) => {
    if (!interactive) return;
    (event.target as Element).setPointerCapture(event.pointerId);
    dragRef.current = { x: event.clientX, domain };
  };
  const onPointerMove = (event: PointerEvent<SVGRectElement>) => {
    const drag = dragRef.current;
    if (!drag || !onDomainChange) return;
    const deltaMs = ((drag.x - event.clientX) / plotWidth) * (drag.domain[1] - drag.domain[0]);
    onDomainChange(panDomain(drag.domain, deltaMs));
  };
  const onPointerUp = (event: PointerEvent<SVGRectElement>) => {
    if (dragRef.current) (event.target as Element).releasePointerCapture(event.pointerId);
    dragRef.current = null;
  };

  const onChartKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    if (!interactive || !onDomainChange || event.target !== event.currentTarget) return;
    const step = span * PAN_STEP;
    const handlers: Record<string, () => void> = {
      '+': () => onDomainChange(zoomDomain(domain, ZOOM_STEP)),
      '=': () => onDomainChange(zoomDomain(domain, ZOOM_STEP)),
      '-': () => onDomainChange(zoomDomain(domain, 1 / ZOOM_STEP)),
      ArrowLeft: () => onDomainChange(panDomain(domain, -step)),
      ArrowRight: () => onDomainChange(panDomain(domain, step)),
      0: () => onFit?.(),
      Home: () => onFit?.(),
    };
    const handler = handlers[event.key];
    if (handler) {
      event.preventDefault();
      handler();
    }
  };

  const onMarkerKeyDown = (event: KeyboardEvent<SVGGElement>, action: () => void) => {
    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault();
      event.stopPropagation();
      action();
    }
  };

  const showHover = (timelineEvent: TimelineChartEvent, target: Element) => {
    const rect = containerRef.current?.getBoundingClientRect();
    const markerRect = target.getBoundingClientRect();
    if (!rect) return;
    setHover({ event: timelineEvent, x: markerRect.left - rect.left + markerRect.width / 2, y: markerRect.top - rect.top + markerRect.height });
  };
  // endregion

  const eventLabel = (event: TimelineChartEvent) => {
    const end = event.event_end_time ? ` - ${fldt(event.event_end_time)}` : '';
    return `${event.title}, ${t_i18n(TIMELINE_KIND_LABELS[event.kind] ?? event.kind)}, ${fldt(event.event_time)}${end}`;
  };

  const renderEvent = (item: Extract<LaneItem, { type: 'event' }>, laneY: number, row: number, color: string) => {
    const { event } = item;
    const centerY = laneY + LANE_PADDING + row * ROW_HEIGHT + ROW_HEIGHT / 2;
    const start = toTime(event.event_time) as number;
    const end = toTime(event.event_end_time);
    const x = scale(new Date(start));
    const approximate = event.precision === 'approximate';
    const selected = event.id === selectedId;
    const opacity = event.hidden ? 0.35 : 1;
    const dash = approximate ? '3 2' : undefined;
    let shape: React.ReactNode;
    if (end !== null) {
      const x2 = Math.max(scale(new Date(end)), x + 3);
      shape = (
        <rect x={x} y={centerY - 5} width={x2 - x} height={10} rx={3} fill={color} fillOpacity={0.35 * opacity} stroke={color} strokeOpacity={opacity} strokeDasharray={dash} />
      );
    } else if (event.source === 'manual') {
      const size = event.pinned ? 7 : 6;
      shape = (
        <rect x={x - size} y={centerY - size} width={size * 2} height={size * 2} transform={`rotate(45 ${x} ${centerY})`} fill={color} fillOpacity={opacity} stroke={colors.background} />
      );
    } else {
      shape = (
        <circle
          cx={x}
          cy={centerY}
          r={event.pinned ? POINT_RADIUS + 2 : POINT_RADIUS}
          fill={approximate ? 'none' : color}
          fillOpacity={opacity}
          stroke={approximate ? color : colors.background}
          strokeOpacity={opacity}
          strokeDasharray={dash}
          strokeWidth={approximate ? 1.5 : 1}
        />
      );
    }
    return (
      <g
        key={event.id}
        className="timeline-event"
        role={onSelect ? 'button' : undefined}
        tabIndex={onSelect ? 0 : undefined}
        aria-label={eventLabel(event)}
        aria-pressed={onSelect ? selected : undefined}
        data-testid={`timeline-event-${event.id}`}
        style={{ cursor: onSelect ? 'pointer' : 'default', outline: 'none' }}
        onClick={() => onSelect?.(event.id)}
        onKeyDown={(keyEvent) => onMarkerKeyDown(keyEvent, () => onSelect?.(event.id))}
        onMouseEnter={(mouseEvent) => showHover(event, mouseEvent.currentTarget)}
        onMouseLeave={() => setHover(null)}
        onFocus={(focusEvent) => showHover(event, focusEvent.currentTarget)}
        onBlur={() => setHover(null)}
      >
        {selected && <circle cx={x} cy={centerY} r={POINT_RADIUS + 6} fill="none" stroke={colors.focus} strokeWidth={2} />}
        {onSelect && !selected && (
          <circle className="timeline-event-focus" cx={x} cy={centerY} r={POINT_RADIUS + 6} fill="none" stroke={colors.focus} strokeWidth={2} />
        )}
        {shape}
        {!compact && (event.pinned || event.source === 'manual') && (
          <text x={x + 10} y={centerY + 4} fill={colors.text} fontSize={11} fillOpacity={opacity}>{truncate(event.title, LABEL_CHARS)}</text>
        )}
      </g>
    );
  };

  const renderCluster = (item: Extract<LaneItem, { type: 'cluster' }>, laneY: number, row: number, color: string) => {
    const { cluster } = item;
    const centerY = laneY + LANE_PADDING + row * ROW_HEIGHT + ROW_HEIGHT / 2;
    const x = scale(new Date(cluster.start + (cluster.end - cluster.start) / 2));
    const label = t_i18n('{count, plural, one {# event} other {# events}} - {from} to {to}', { values: { count: cluster.events.length, from: fldt(new Date(cluster.start)), to: fldt(new Date(cluster.end)) } });
    const select = () => onClusterSelect?.([cluster.start, cluster.end]);
    return (
      <g
        key={cluster.id}
        className="timeline-cluster"
        role={onClusterSelect ? 'button' : undefined}
        tabIndex={onClusterSelect ? 0 : undefined}
        aria-label={label}
        style={{ cursor: onClusterSelect ? 'zoom-in' : 'default', outline: 'none' }}
        onClick={select}
        onKeyDown={(keyEvent) => onMarkerKeyDown(keyEvent, select)}
        data-testid={`timeline-cluster-${cluster.id}`}
      >
        <title>{label}</title>
        {onClusterSelect && (
          <circle className="timeline-cluster-focus" cx={x} cy={centerY} r={13} fill="none" stroke={colors.focus} strokeWidth={2} />
        )}
        <circle cx={x} cy={centerY} r={9} fill={color} fillOpacity={0.85} stroke={colors.background} />
        <text x={x} y={centerY + 3.5} fill={colors.background} fontSize={9.5} fontWeight="bold" textAnchor="middle">
          {cluster.events.length > 99 ? '99+' : cluster.events.length}
        </text>
      </g>
    );
  };

  const nowX = scale(new Date());
  const anchorEntries = TIMELINE_ANCHOR_KEYS
    .map((key) => ({ key, time: toTime(anchors?.[key]) }))
    .filter((anchor): anchor is { key: TimelineAnchorKey; time: number } => anchor.time !== null)
    .map((anchor) => ({ ...anchor, x: scale(new Date(anchor.time)) }))
    .filter((anchor) => anchor.x >= plotLeft && anchor.x <= plotRight);
  // Anchors close in time get their labels on successive rows instead of overlapping, kept inside the plot
  const anchorLabels = compact ? [] : layoutAnchorLabels(
    anchorEntries.map((anchor) => ({ key: anchor.key, x: anchor.x, label: t_i18n(TIMELINE_ANCHOR_LABELS[anchor.key]) })),
    plotLeft,
    plotRight,
  );
  const anchorRows = anchorLabels.reduce((rows, label) => Math.max(rows, label.row + 1), 1);
  const totalHeight = lanesBottom + (compact ? 4 : ANCHOR_HEIGHT * anchorRows + 6);

  return (
    <div
      ref={containerRef}
      className="timeline-lanes"
      style={{ position: 'relative', width: '100%' }}
      tabIndex={interactive ? 0 : undefined}
      role={interactive ? 'group' : undefined}
      aria-label={interactive ? `${ariaLabel}. ${t_i18n('Use plus and minus to zoom, left and right arrows to pan, 0 to fit')}` : undefined}
      onKeyDown={onChartKeyDown}
      data-testid="timeline-lanes"
    >
      {/* Keyboard focus only: a ring inside the chart, and around the marker of an event or a cluster (the browser outline would frame its whole group) */}
      <style>
        {`.timeline-lanes { outline: none; } .timeline-lanes:focus-visible { outline: 2px solid ${colors.focus}; outline-offset: -2px; } `
          + '.timeline-cluster-focus, .timeline-event-focus { visibility: hidden; } '
          + '.timeline-cluster:focus-visible .timeline-cluster-focus, .timeline-event:focus-visible .timeline-event-focus { visibility: visible; }'}
      </style>
      <svg
        ref={svgRef}
        width={width}
        height={totalHeight}
        viewBox={`0 0 ${width} ${totalHeight}`}
        // An image hides its descendants from assistive technologies: with focusable events or clusters, it is a group
        role={onSelect || onClusterSelect ? 'group' : 'img'}
        aria-label={ariaLabel}
        fontFamily={colors.fontFamily}
        fontSize={11}
        style={{ display: 'block', userSelect: 'none', touchAction: interactive ? 'none' : 'auto' }}
      >
        <defs>
          <clipPath id={clipId}>
            <rect x={plotLeft} y={0} width={plotWidth} height={totalHeight} />
          </clipPath>
        </defs>
        <rect x={0} y={0} width={width} height={totalHeight} fill={colors.background} />
        {laneLayouts.map((layout, index) => (
          <g key={layout.lane}>
            <rect x={0} y={layout.y} width={width} height={layout.height} fill={index % 2 === 0 ? colors.laneBackground : 'transparent'} />
            <rect x={8} y={layout.y + layout.height / 2 - 7} width={4} height={14} rx={2} fill={colors.lanes[layout.lane]} />
            <text x={18} y={layout.y + layout.height / 2 + 4} fill={colors.text} fontSize={compact ? 11 : 12} fontWeight="bold">
              <title>{t_i18n(TIMELINE_LANE_LABELS[layout.lane])}</title>
              {compact ? truncate(t_i18n(TIMELINE_LANE_LABELS[layout.lane]), COMPACT_LABEL_CHARS) : t_i18n(TIMELINE_LANE_LABELS[layout.lane])}
            </text>
          </g>
        ))}
        <line x1={plotLeft} y1={AXIS_HEIGHT - 6} x2={plotRight} y2={AXIS_HEIGHT - 6} stroke={colors.grid} />
        {ticks.map((tick) => {
          const x = scale(tick);
          return (
            <g key={tick.getTime()}>
              <line x1={x} y1={AXIS_HEIGHT - 10} x2={x} y2={lanesBottom} stroke={colors.grid} strokeDasharray="2 4" />
              <text x={x} y={AXIS_HEIGHT - 14} fill={colors.textSecondary} textAnchor={tickAnchor(x)}>{formatTick(tick)}</text>
            </g>
          );
        })}
        {interactive && (
          <rect
            x={plotLeft}
            y={AXIS_HEIGHT}
            width={plotWidth}
            height={lanesBottom - AXIS_HEIGHT}
            fill="transparent"
            style={{ cursor: dragRef.current ? 'grabbing' : 'grab' }}
            onPointerDown={onPointerDown}
            onPointerMove={onPointerMove}
            onPointerUp={onPointerUp}
            onPointerCancel={onPointerUp}
          />
        )}
        <g clipPath={`url(#${clipId})`}>
          {nowX >= plotLeft && nowX <= plotRight && (
            <line x1={nowX} y1={AXIS_HEIGHT - 6} x2={nowX} y2={lanesBottom} stroke={colors.focus} strokeDasharray="1 3" strokeOpacity={0.6} />
          )}
          {anchorEntries.map((anchor) => (
            <line key={anchor.key} x1={anchor.x} y1={AXIS_HEIGHT - 6} x2={anchor.x} y2={lanesBottom + 4} stroke={colors.anchor} strokeDasharray="5 3" strokeOpacity={0.7} />
          ))}
          {anchorLabels.map((anchor) => (
            <text key={anchor.key} x={anchor.x} y={lanesBottom + ANCHOR_HEIGHT * (anchor.row + 1)} fill={colors.text} fontSize={10} textAnchor="middle">
              {anchor.label}
            </text>
          ))}
          {laneLayouts.map((layout) => {
            const color = colors.lanes[layout.lane];
            return (
              <g key={`items-${layout.lane}`}>
                {layout.items.map((item) => {
                  const row = Math.min(layout.rows.get(item.id) ?? 0, layout.maxRows - 1);
                  return item.type === 'event'
                    ? renderEvent(item, layout.y, row, color)
                    : renderCluster(item, layout.y, row, color);
                })}
              </g>
            );
          })}
        </g>
      </svg>
      {hover && (
        <div
          role="tooltip"
          style={{
            position: 'absolute',
            left: Math.min(Math.max(hover.x - 140, 0), Math.max(width - 280, 0)),
            top: hover.y + 8,
            width: 280,
            padding: theme.spacing(1, 1.5),
            borderRadius: theme.shape.borderRadius,
            background: colors.background,
            border: `1px solid ${colors.grid}`,
            boxShadow: colors.shadow,
            pointerEvents: 'none',
            zIndex: 2,
            color: colors.text,
          }}
        >
          <Text variant="content-compact-bold" as="div">{hover.event.title}</Text>
          <Text variant="content-caption" as="div" style={{ color: colors.textSecondary }}>
            {hover.event.event_end_time
              ? t_i18n('From {start} to {end}', { values: { start: fldt(hover.event.event_time), end: fldt(hover.event.event_end_time) } })
              : fldt(hover.event.event_time)}
          </Text>
          {hover.event.precision === 'approximate' && (
            <Text variant="content-caption" as="div" style={{ color: colors.textSecondary }}>{t_i18n('Approximate time')}</Text>
          )}
          {hoverState && (
            <Text variant="content-compact-medium" as="div">{t_i18n(hoverState.label)}</Text>
          )}
          <Text variant="content-caption" as="div" style={{ color: colors.textSecondary }}>
            {t_i18n('{kind} in the {lane} lane', {
              values: {
                kind: t_i18n(TIMELINE_KIND_LABELS[hover.event.kind] ?? hover.event.kind),
                lane: t_i18n(TIMELINE_LANE_LABELS[hover.event.lane as TimelineLane] ?? hover.event.lane),
              },
            })}
          </Text>
          <Text variant="content-caption" as="div" style={{ color: colors.textSecondary }} data-testid="timeline-tooltip-source">
            {hover.event.source === 'manual' ? t_i18n('Analyst milestone') : t_i18n('Derived from the knowledge')}
          </Text>
          {hover.event.annotation && (
            <Text variant="content-caption" as="div" style={{ marginTop: theme.spacing(0.5) }}>{hover.event.annotation}</Text>
          )}
        </div>
      )}
    </div>
  );
};

export default ContainerTimelineLanes;
