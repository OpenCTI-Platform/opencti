import { isTimelineContextWindow } from './timeline-rules';
import { TIMELINE_ANCHOR_KEYS, type TimelineAnchorKey, type TimelineAnchors, type TimelineLaneValue } from './timeline-types';

export interface TimelineExportEvent {
  id: string;
  lane: TimelineLaneValue;
  kind: string;
  rule_id?: string | null;
  event_time: string;
  event_end_time?: string | null;
  open_ended?: boolean | null;
  precision: string;
  title: string;
  description?: string | null;
  element_name?: string | null;
  element_type?: string | null;
  source: string;
  pinned: boolean;
  hidden: boolean;
  annotation?: string | null;
}

export interface TimelineExportInput {
  containerName: string;
  containerType: string;
  events: TimelineExportEvent[];
  anchors: TimelineAnchors | null;
  generatedAt: string;
  labels?: Record<string, string>;
  /** Lanes of the view the export was made from; none means every lane. */
  lanes?: readonly string[] | null;
}

// Fixed palette: an export is a standalone document and must render the same in every theme.
// The lane and text tones are the ones of the light theme of the platform (design-system light tokens).
const TEXT_COLOR = '#18191b';
const TEXT_SECONDARY_COLOR = '#494a50';
const LANE_COLORS: Record<TimelineLaneValue, string> = {
  adversary: '#b8180a',
  evidence: '#0015a8',
  response: '#117916',
  knowledge: '#009474',
  detection: '#b8550a',
  custom: TEXT_SECONDARY_COLOR,
};

const DEFAULT_LABELS: Record<string, string> = {
  title: 'Timeline',
  generated_at: 'Generated at',
  anchors: 'Anchors',
  events: 'Events',
  no_events: 'No event',
  'lane.adversary': 'Adversary',
  'lane.evidence': 'Evidence',
  'lane.response': 'Response',
  'lane.knowledge': 'Knowledge',
  'lane.detection': 'Detection',
  'lane.custom': 'Custom',
  'anchor.first_adversary_activity': 'First adversary activity',
  'anchor.first_detection': 'First detection',
  'anchor.first_response': 'First response',
  'anchor.containment': 'Containment',
  'anchor.closure': 'Closure',
  'column.time': 'Time',
  'column.end_time': 'End time',
  'column.lane': 'Lane',
  'column.kind': 'Kind',
  'column.precision': 'Precision',
  'column.title': 'Title',
  'column.element': 'Element',
  'column.source': 'Source',
  'column.annotation': 'Annotation',
  still_open: 'Still open',
  context_window: 'Global first and last seen of the entity, context only: not dated in this incident',
};

const label = (input: TimelineExportInput, key: string, fallback?: string) => input.labels?.[key] ?? DEFAULT_LABELS[key] ?? fallback ?? key;

export const escapeXml = (value: string | null | undefined): string => {
  if (value === null || value === undefined) return '';
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
};

const pad = (value: number) => String(value).padStart(2, '0');
export const formatExportDate = (value: string | null | undefined): string => {
  if (!value) return '';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '';
  return `${date.getUTCFullYear()}-${pad(date.getUTCMonth() + 1)}-${pad(date.getUTCDate())} ${pad(date.getUTCHours())}:${pad(date.getUTCMinutes())} UTC`;
};

// region CSV
const CSV_COLUMNS = ['time', 'end_time', 'lane', 'kind', 'precision', 'title', 'element', 'element_type', 'source', 'pinned', 'hidden', 'annotation', 'description'] as const;

/** Quote a CSV cell (RFC 4180) and neutralize spreadsheet formulas. */
export const csvCell = (value: string | number | boolean | null | undefined): string => {
  if (value === null || value === undefined) return '';
  let text = String(value);
  if (/^[=+\-@\t\r]/.test(text)) text = `'${text}`;
  if (/[",\r\n]/.test(text)) return `"${text.replace(/"/g, '""')}"`;
  return text;
};

export const renderTimelineCsv = (input: TimelineExportInput): string => {
  const lines = [CSV_COLUMNS.join(',')];
  input.events.forEach((event) => {
    lines.push([
      new Date(event.event_time).toISOString(),
      event.event_end_time ? new Date(event.event_end_time).toISOString() : '',
      event.lane,
      event.kind,
      event.precision,
      event.title,
      event.element_name ?? '',
      event.element_type ?? '',
      event.source,
      event.pinned,
      event.hidden,
      event.annotation ?? '',
      event.description ?? '',
    ].map(csvCell).join(','));
  });
  return `${lines.join('\r\n')}\r\n`;
};
// endregion

// region SVG
const SVG_WIDTH = 1200;
const LABEL_WIDTH = 140;
const AXIS_HEIGHT = 40;
const PADDING = 16;
const ROW_HEIGHT = 18;
const LANE_PADDING = 9;
// Beyond these rows, the items left of a lane are drawn as count bubbles on its last row, like in the Timeline tab
const MAX_LANE_ROWS = 6;
const DOT_RADIUS = 4;
const PINNED_DOT_RADIUS = 6;
const BUBBLE_RADIUS = 8;
const LEGEND_HEIGHT = 20;
const CONTEXT_STYLE = 'fill-opacity="0.12" stroke-opacity="0.45"';
const ITEM_GAP = 4;
const MAX_LABEL_CHARS = 28;
// Approximate widths of a character of the 11 px event labels and of the 10 px anchor labels
const LABEL_CHAR_WIDTH = 6;
const ANCHOR_LABEL_CHAR_WIDTH = 5.6;
const ANCHOR_ROW_HEIGHT = 14;
const TICK_COUNT = 6;

const truncate = (value: string, max: number) => (value.length > max ? `${value.slice(0, max - 3)}...` : value);

const niceTicks = (from: number, to: number, count: number): number[] => {
  if (to <= from) return [from];
  const step = (to - from) / count;
  return Array.from({ length: count + 1 }, (_, index) => from + index * step);
};

// The lanes from top to bottom, as the timeline view draws them
export const TIMELINE_EXPORT_LANE_ORDER: readonly TimelineLaneValue[] = ['adversary', 'detection', 'response', 'evidence', 'knowledge', 'custom'];

interface SvgSpan {
  id: string;
  x1: number;
  x2: number;
}

/** Greedy interval partitioning: the row of each span so that the spans of a row never overlap. */
export const layoutExportRows = (spans: SvgSpan[], gap = ITEM_GAP): { rows: Map<string, number>; rowCount: number } => {
  const sorted = [...spans].sort((a, b) => a.x1 - b.x1 || a.x2 - b.x2);
  const rowEnds: number[] = [];
  const rows = new Map<string, number>();
  sorted.forEach((span) => {
    let row = rowEnds.findIndex((end) => end + gap <= span.x1);
    if (row < 0) {
      row = rowEnds.length;
      rowEnds.push(span.x2);
    } else {
      rowEnds[row] = span.x2;
    }
    rows.set(span.id, row);
  });
  return { rows, rowCount: Math.max(rowEnds.length, 1) };
};

export type ExportLaneItem
  = | { type: 'window'; id: string; x1: number; x2: number; event: TimelineExportEvent; open: boolean }
    | { type: 'point'; id: string; x1: number; x2: number; x: number; event: TimelineExportEvent; labelled: boolean }
    | { type: 'bubble'; id: string; x1: number; x2: number; x: number; events: TimelineExportEvent[] };

export interface ExportLaneLayout {
  lane: TimelineLaneValue;
  rowCount: number;
  items: Array<ExportLaneItem & { row: number }>;
}

/**
 * Layout of the events of one lane: windows and labelled events (pinned, milestones) are drawn on their own, dots closer
 * than they can be told apart become one count bubble, overlapping items are spread over rows, and the items beyond the
 * last row a lane draws are grouped into count bubbles on that row.
 */
export const layoutExportLane = (
  lane: TimelineLaneValue,
  events: TimelineExportEvent[],
  x: (time: number) => number,
  plotRight: number,
): ExportLaneLayout => {
  const items: ExportLaneItem[] = [];
  const dots: Array<{ x: number; event: TimelineExportEvent }> = [];
  events.forEach((event) => {
    const startX = x(new Date(event.event_time).getTime());
    const isOpen = !!event.open_ended && !event.event_end_time;
    if (event.event_end_time || isOpen) {
      const endX = isOpen ? plotRight : Math.max(x(new Date(event.event_end_time as string).getTime()), startX + 2);
      items.push({ type: 'window', id: event.id, x1: startX, x2: endX, event, open: isOpen });
      return;
    }
    const labelled = event.pinned || event.source === 'manual';
    if (labelled) {
      const labelWidth = Math.min(event.title.length, MAX_LABEL_CHARS) * LABEL_CHAR_WIDTH;
      items.push({ type: 'point', id: event.id, x: startX, x1: startX - PINNED_DOT_RADIUS, x2: startX + PINNED_DOT_RADIUS + 4 + labelWidth, event, labelled });
      return;
    }
    dots.push({ x: startX, event });
  });
  // Dots closer than two of them can be told apart are one count bubble
  dots.sort((a, b) => a.x - b.x);
  let group: typeof dots = [];
  const flush = () => {
    if (group.length === 1) {
      const [{ x: dotX, event }] = group;
      items.push({ type: 'point', id: event.id, x: dotX, x1: dotX - DOT_RADIUS, x2: dotX + DOT_RADIUS, event, labelled: false });
    } else if (group.length > 1) {
      const first = group[0].x;
      const last = group[group.length - 1].x;
      const center = (first + last) / 2;
      items.push({ type: 'bubble', id: `bubble-${group[0].event.id}`, x: center, x1: Math.min(first, center - BUBBLE_RADIUS), x2: Math.max(last, center + BUBBLE_RADIUS), events: group.map((dot) => dot.event) });
    }
    group = [];
  };
  dots.forEach((dot) => {
    if (group.length > 0 && dot.x - group[group.length - 1].x > DOT_RADIUS * 2 + 1) flush();
    group.push(dot);
  });
  flush();
  const { rows, rowCount } = layoutExportRows(items);
  if (rowCount <= MAX_LANE_ROWS) {
    return { lane, rowCount, items: items.map((item) => ({ ...item, row: rows.get(item.id) ?? 0 })) };
  }
  const lastRow = MAX_LANE_ROWS - 1;
  const kept = items.filter((item) => (rows.get(item.id) ?? 0) < lastRow).map((item) => ({ ...item, row: rows.get(item.id) ?? 0 }));
  const overflow = items.filter((item) => (rows.get(item.id) ?? 0) >= lastRow).sort((a, b) => a.x1 - b.x1 || a.x2 - b.x2);
  const bubbles: Array<ExportLaneItem & { row: number }> = [];
  let current: ExportLaneItem[] = [];
  let currentEnd = Number.NEGATIVE_INFINITY;
  const flushOverflow = () => {
    if (current.length === 0) return;
    const overflowEvents = current.flatMap((item) => (item.type === 'bubble' ? item.events : [item.event]));
    const center = Math.min(...current.map((item) => item.x1)) + BUBBLE_RADIUS;
    bubbles.push({ type: 'bubble', id: `overflow-${current[0].id}`, x: center, x1: center - BUBBLE_RADIUS, x2: center + BUBBLE_RADIUS, events: overflowEvents, row: lastRow });
    current = [];
  };
  overflow.forEach((item) => {
    if (current.length > 0 && item.x1 > currentEnd + ITEM_GAP) {
      flushOverflow();
      currentEnd = Number.NEGATIVE_INFINITY;
    }
    current.push(item);
    currentEnd = Math.max(currentEnd, item.x2);
  });
  flushOverflow();
  return { lane, rowCount: MAX_LANE_ROWS, items: [...kept, ...bubbles] };
};

export interface ExportAnchorLabel {
  key: string;
  anchorX: number;
  x: number;
  label: string;
  row: number;
}

/** Anchor labels kept inside the plot, on successive rows when anchors close in time would write over each other. */
export const layoutExportAnchorLabels = (anchors: Array<{ key: string; x: number; label: string }>, plotLeft: number, plotRight: number): ExportAnchorLabel[] => {
  const placed = anchors.map((anchor) => {
    const halfWidth = (anchor.label.length * ANCHOR_LABEL_CHAR_WIDTH) / 2;
    const labelX = Math.min(Math.max(anchor.x, plotLeft + halfWidth), Math.max(plotLeft + halfWidth, plotRight - halfWidth));
    return { ...anchor, labelX, x1: labelX - halfWidth, x2: labelX + halfWidth };
  });
  const { rows } = layoutExportRows(placed.map((anchor) => ({ id: anchor.key, x1: anchor.x1, x2: anchor.x2 })), 8);
  return placed.map((anchor) => ({ key: anchor.key, anchorX: anchor.x, x: anchor.labelX, label: anchor.label, row: rows.get(anchor.key) ?? 0 }));
};

const laneHeight = (rowCount: number) => LANE_PADDING * 2 + Math.max(rowCount, 1) * ROW_HEIGHT;

/** Render the timeline as a standalone SVG (lanes, events, windows, anchors). */
export const renderTimelineSvg = (input: TimelineExportInput): string => {
  // The lanes selected in the view, empty ones included; without a selection, the core lanes and the custom lane when it is used
  const selected = input.lanes && input.lanes.length > 0 ? new Set(input.lanes) : null;
  const lanes = TIMELINE_EXPORT_LANE_ORDER.filter((lane) => (selected ? selected.has(lane) : lane !== 'custom' || input.events.some((e) => e.lane === 'custom')));
  const plotLeft = LABEL_WIDTH + PADDING;
  const plotRight = SVG_WIDTH - PADDING;
  const times: number[] = [];
  input.events.forEach((event) => {
    times.push(new Date(event.event_time).getTime());
    if (event.event_end_time) times.push(new Date(event.event_end_time).getTime());
  });
  const anchorValues = TIMELINE_ANCHOR_KEYS
    .map((key) => ({ key, value: input.anchors?.[key] }))
    .filter((anchor): anchor is { key: TimelineAnchorKey; value: string } => !!anchor.value);
  times.push(...anchorValues.map((anchor) => new Date(anchor.value).getTime()));
  const parts: string[] = [];
  const open = (height: number) => {
    parts.push(`<svg xmlns="http://www.w3.org/2000/svg" width="${SVG_WIDTH}" height="${height}" viewBox="0 0 ${SVG_WIDTH} ${height}" font-family="Helvetica, Arial, sans-serif" font-size="11">`);
    parts.push(`<rect x="0" y="0" width="${SVG_WIDTH}" height="${height}" fill="#ffffff"/>`);
  };
  const drawLanes = (layouts: Array<{ lane: TimelineLaneValue; y: number; height: number }>) => {
    layouts.forEach(({ lane, y, height }, index) => {
      parts.push(`<rect x="0" y="${y}" width="${SVG_WIDTH}" height="${height}" fill="${index % 2 === 0 ? '#f5f7fa' : '#ffffff'}"/>`);
      parts.push(`<rect x="${PADDING}" y="${y + LANE_PADDING + ROW_HEIGHT / 2 - 6}" width="4" height="12" fill="${LANE_COLORS[lane]}"/>`);
      parts.push(`<text x="${PADDING + 10}" y="${y + LANE_PADDING + ROW_HEIGHT / 2 + 4}" fill="${TEXT_COLOR}" font-weight="bold">${escapeXml(label(input, `lane.${lane}`))}</text>`);
    });
  };
  if (times.length === 0) {
    const emptyLayouts = lanes.map((lane, index) => ({ lane, y: PADDING + AXIS_HEIGHT + index * laneHeight(1), height: laneHeight(1) }));
    open(PADDING * 2 + AXIS_HEIGHT + lanes.length * laneHeight(1));
    drawLanes(emptyLayouts);
    parts.push(`<text x="${plotLeft}" y="${PADDING + AXIS_HEIGHT / 2}" fill="${TEXT_SECONDARY_COLOR}">${escapeXml(label(input, 'no_events'))}</text>`);
    parts.push('</svg>');
    return parts.join('');
  }
  let min = Math.min(...times);
  let max = Math.max(...times);
  if (max === min) {
    min -= 3600000;
    max += 3600000;
  }
  const margin = (max - min) * 0.03;
  min -= margin;
  max += margin;
  const x = (time: number) => plotLeft + ((time - min) / (max - min)) * (plotRight - plotLeft);
  // Lanes grow with the rows their overlapping items need
  const laneLayouts = lanes.map((lane) => layoutExportLane(lane, input.events.filter((event) => event.lane === lane), x, plotRight));
  const lanesTop = PADDING + AXIS_HEIGHT;
  let laneY = lanesTop;
  const positioned = laneLayouts.map((layout) => {
    const height = laneHeight(layout.rowCount);
    const entry = { ...layout, y: laneY, height };
    laneY += height;
    return entry;
  });
  const lanesBottom = laneY;
  const anchorLabels = layoutExportAnchorLabels(
    anchorValues.map((anchor) => ({ key: anchor.key, x: x(new Date(anchor.value).getTime()), label: label(input, `anchor.${anchor.key}`) })),
    plotLeft,
    plotRight,
  );
  const anchorRows = anchorLabels.length > 0 ? Math.max(...anchorLabels.map((anchor) => anchor.row)) + 1 : 0;
  const hasContextWindows = input.events.some((event) => lanes.includes(event.lane) && isTimelineContextWindow(event));
  const legendTop = lanesBottom + anchorRows * ANCHOR_ROW_HEIGHT;
  const height = legendTop + (hasContextWindows ? LEGEND_HEIGHT : 0) + PADDING;
  open(height);
  drawLanes(positioned);
  // Axis: the first and last dates are aligned on the edges of the plot, never cut by the edges of the image
  const axisY = lanesTop - 8;
  parts.push(`<line x1="${plotLeft}" y1="${axisY}" x2="${plotRight}" y2="${axisY}" stroke="#9aa5b1"/>`);
  const ticks = niceTicks(min, max, TICK_COUNT);
  ticks.forEach((tick, index) => {
    const tickX = x(tick).toFixed(1);
    let anchor = 'middle';
    if (index === 0) anchor = 'start';
    else if (index === ticks.length - 1) anchor = 'end';
    parts.push(`<line x1="${tickX}" y1="${axisY - 4}" x2="${tickX}" y2="${lanesBottom}" stroke="#e4e7eb"/>`);
    parts.push(`<text x="${tickX}" y="${axisY - 8}" fill="${TEXT_SECONDARY_COLOR}" text-anchor="${anchor}">${escapeXml(formatExportDate(new Date(tick).toISOString()))}</text>`);
  });
  // Events
  positioned.forEach((layout) => {
    const color = LANE_COLORS[layout.lane];
    layout.items.forEach((item) => {
      const centerY = layout.y + LANE_PADDING + item.row * ROW_HEIGHT + ROW_HEIGHT / 2;
      if (item.type === 'bubble') {
        const tooltip = item.events.slice(0, 20).map((event) => `${formatExportDate(event.event_time)} - ${event.title}`).join('\n');
        parts.push(`<g><title>${escapeXml(tooltip)}</title>`);
        parts.push(`<circle cx="${item.x.toFixed(1)}" cy="${centerY}" r="${BUBBLE_RADIUS}" fill="${color}" fill-opacity="0.85" stroke="#ffffff"/>`);
        parts.push(`<text x="${item.x.toFixed(1)}" y="${centerY + 3.5}" fill="#ffffff" text-anchor="middle" font-size="10" font-weight="bold">${item.events.length}</text></g>`);
        return;
      }
      const { event } = item;
      const opacity = event.precision === 'approximate' ? 0.5 : 1;
      const stillOpen = item.type === 'window' && item.open ? ` - ${label(input, 'still_open')}` : '';
      const title = `<title>${escapeXml(`${formatExportDate(event.event_time)} - ${event.title}${stillOpen}`)}</title>`;
      // The global first and last seen of an entity are context: lighter, explained by the legend
      const context = isTimelineContextWindow(event);
      if (item.type === 'window') {
        const width = Math.max(item.x2 - item.x1, 2);
        // A window without a known end runs to the right edge of the plot, its outline dashed
        let style = item.open
          ? `fill-opacity="${opacity * 0.3}" stroke="${color}" stroke-dasharray="4 3"`
          : `fill-opacity="${opacity * 0.6}" stroke="${color}"`;
        if (context) style = `${CONTEXT_STYLE} stroke="${color}"${item.open ? ' stroke-dasharray="4 3"' : ''}`;
        parts.push(`<rect x="${item.x1.toFixed(1)}" y="${centerY - 5}" width="${width.toFixed(1)}" height="10" rx="3" fill="${color}" ${style}>${title}</rect>`);
        return;
      }
      const dotStyle = context ? `${CONTEXT_STYLE} stroke="${color}"` : `fill-opacity="${opacity}" stroke="#ffffff"`;
      parts.push(`<circle cx="${item.x.toFixed(1)}" cy="${centerY}" r="${event.pinned ? PINNED_DOT_RADIUS : DOT_RADIUS}" fill="${color}" ${dotStyle}>${title}</circle>`);
      if (item.labelled) {
        parts.push(`<text x="${(item.x + PINNED_DOT_RADIUS + 3).toFixed(1)}" y="${centerY + 4}" fill="${TEXT_COLOR}">${escapeXml(truncate(event.title, MAX_LABEL_CHARS))}</text>`);
      }
    });
  });
  // Anchors: a dashed line across the lanes, the labels below them on as many rows as needed to stay readable
  anchorLabels.forEach((anchor) => {
    const anchorX = anchor.anchorX.toFixed(1);
    const labelY = lanesBottom + (anchor.row + 1) * ANCHOR_ROW_HEIGHT - 3;
    parts.push(`<line x1="${anchorX}" y1="${lanesTop}" x2="${anchorX}" y2="${lanesBottom + anchor.row * ANCHOR_ROW_HEIGHT + 3}" stroke="${TEXT_COLOR}" stroke-dasharray="4 3"/>`);
    parts.push(`<text x="${anchor.x.toFixed(1)}" y="${labelY}" fill="${TEXT_COLOR}" text-anchor="middle" font-size="10">${escapeXml(anchor.label)}</text>`);
  });
  if (hasContextWindows) {
    const legendY = legendTop + LEGEND_HEIGHT / 2;
    parts.push(`<g data-legend="context_window"><rect x="${plotLeft}" y="${legendY - 5}" width="24" height="10" rx="3" fill="${LANE_COLORS.adversary}" ${CONTEXT_STYLE} stroke="${LANE_COLORS.adversary}"/>`);
    parts.push(`<text x="${plotLeft + 30}" y="${legendY + 4}" fill="${TEXT_SECONDARY_COLOR}" font-size="10">${escapeXml(label(input, 'context_window'))}</text></g>`);
  }
  parts.push('</svg>');
  return parts.join('');
};
// endregion

// region HTML (consumed by the built-in HTML to PDF export of the front end)
/**
 * The drawing comes first, alone on its page; the headline dates and the events start on the next page, where the
 * `pdf-pagebreak-before` class asks the PDF export to break.
 */
export const renderTimelineHtml = (input: TimelineExportInput): string => {
  const anchorsRows = TIMELINE_ANCHOR_KEYS.map((key) => {
    const value = input.anchors?.[key];
    return `<tr><td>${escapeXml(label(input, `anchor.${key}`))}</td><td>${escapeXml(value ? formatExportDate(value) : '-')}</td></tr>`;
  }).join('');
  const eventRows = input.events.map((event) => [
    formatExportDate(event.event_time),
    event.open_ended && !event.event_end_time ? label(input, 'still_open') : formatExportDate(event.event_end_time),
    label(input, `lane.${event.lane}`),
    label(input, `kind.${event.kind}`, event.kind),
    label(input, `precision.${event.precision}`, event.precision),
    event.title,
    event.element_name ?? '',
    event.annotation ?? '',
  ].map((cell) => `<td>${escapeXml(cell)}</td>`).join('')).map((cells) => `<tr>${cells}</tr>`).join('');
  const headers = ['time', 'end_time', 'lane', 'kind', 'precision', 'title', 'element', 'annotation']
    .map((key) => `<th>${escapeXml(label(input, `column.${key}`))}</th>`).join('');
  return [
    '<div>',
    `<h1>${escapeXml(`${label(input, 'title')} - ${input.containerName}`)}</h1>`,
    `<p>${escapeXml(`${input.containerType} - ${label(input, 'generated_at')} ${formatExportDate(input.generatedAt)}`)}</p>`,
    renderTimelineSvg(input),
    `<h2 class="pdf-pagebreak-before">${escapeXml(label(input, 'anchors'))}</h2>`,
    `<table><tbody>${anchorsRows}</tbody></table>`,
    `<h2>${escapeXml(label(input, 'events'))}</h2>`,
    input.events.length > 0
      ? `<table><thead><tr>${headers}</tr></thead><tbody>${eventRows}</tbody></table>`
      : `<p>${escapeXml(label(input, 'no_events'))}</p>`,
    '</div>',
  ].join('');
};
// endregion
