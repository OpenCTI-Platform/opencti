import { TIMELINE_ANCHOR_KEYS, type TimelineAnchors, type TimelineLaneValue } from './timeline-types';

export interface TimelineExportEvent {
  id: string;
  lane: TimelineLaneValue;
  kind: string;
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
const AXIS_HEIGHT = 48;
const LANE_HEIGHT = 56;
const PADDING = 16;
const MAX_LABEL_CHARS = 28;

const truncate = (value: string, max: number) => (value.length > max ? `${value.slice(0, max - 3)}...` : value);

const niceTicks = (from: number, to: number, count: number): number[] => {
  if (to <= from) return [from];
  const step = (to - from) / count;
  return Array.from({ length: count + 1 }, (_, index) => from + index * step);
};

// The lanes from top to bottom, as the timeline view draws them
export const TIMELINE_EXPORT_LANE_ORDER: readonly TimelineLaneValue[] = ['adversary', 'detection', 'response', 'evidence', 'knowledge', 'custom'];

/** Render the timeline as a standalone SVG (lanes, events, windows, anchors). */
export const renderTimelineSvg = (input: TimelineExportInput): string => {
  // The lanes selected in the view, empty ones included; without a selection, the core lanes and the custom lane when it is used
  const selected = input.lanes && input.lanes.length > 0 ? new Set(input.lanes) : null;
  const lanes = TIMELINE_EXPORT_LANE_ORDER.filter((lane) => (selected ? selected.has(lane) : lane !== 'custom' || input.events.some((e) => e.lane === 'custom')));
  const height = AXIS_HEIGHT + lanes.length * LANE_HEIGHT + PADDING * 2;
  const plotLeft = LABEL_WIDTH + PADDING;
  const plotRight = SVG_WIDTH - PADDING;
  const times: number[] = [];
  input.events.forEach((event) => {
    times.push(new Date(event.event_time).getTime());
    if (event.event_end_time) times.push(new Date(event.event_end_time).getTime());
  });
  const anchorTimes = input.anchors
    ? TIMELINE_ANCHOR_KEYS.map((key) => input.anchors?.[key]).filter((v): v is string => !!v).map((v) => new Date(v).getTime())
    : [];
  times.push(...anchorTimes);
  const parts: string[] = [];
  parts.push(`<svg xmlns="http://www.w3.org/2000/svg" width="${SVG_WIDTH}" height="${height}" viewBox="0 0 ${SVG_WIDTH} ${height}" font-family="Helvetica, Arial, sans-serif" font-size="11">`);
  parts.push(`<rect x="0" y="0" width="${SVG_WIDTH}" height="${height}" fill="#ffffff"/>`);
  lanes.forEach((lane, index) => {
    const y = PADDING + AXIS_HEIGHT + index * LANE_HEIGHT;
    parts.push(`<rect x="0" y="${y}" width="${SVG_WIDTH}" height="${LANE_HEIGHT}" fill="${index % 2 === 0 ? '#f5f7fa' : '#ffffff'}"/>`);
    parts.push(`<rect x="${PADDING}" y="${y + LANE_HEIGHT / 2 - 6}" width="4" height="12" fill="${LANE_COLORS[lane]}"/>`);
    parts.push(`<text x="${PADDING + 10}" y="${y + LANE_HEIGHT / 2 + 4}" fill="${TEXT_COLOR}" font-weight="bold">${escapeXml(label(input, `lane.${lane}`))}</text>`);
  });
  if (times.length === 0) {
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
  // Axis
  const axisY = PADDING + AXIS_HEIGHT - 8;
  parts.push(`<line x1="${plotLeft}" y1="${axisY}" x2="${plotRight}" y2="${axisY}" stroke="#9aa5b1"/>`);
  niceTicks(min, max, 6).forEach((tick) => {
    const tickX = x(tick).toFixed(1);
    parts.push(`<line x1="${tickX}" y1="${axisY - 4}" x2="${tickX}" y2="${height - PADDING}" stroke="#e4e7eb"/>`);
    parts.push(`<text x="${tickX}" y="${axisY - 8}" fill="${TEXT_SECONDARY_COLOR}" text-anchor="middle">${escapeXml(formatExportDate(new Date(tick).toISOString()))}</text>`);
  });
  // Events
  input.events.forEach((event) => {
    const laneIndex = lanes.indexOf(event.lane);
    if (laneIndex < 0) return;
    const laneY = PADDING + AXIS_HEIGHT + laneIndex * LANE_HEIGHT;
    const centerY = laneY + LANE_HEIGHT / 2;
    const startX = x(new Date(event.event_time).getTime());
    const color = LANE_COLORS[event.lane];
    const opacity = event.precision === 'approximate' ? 0.5 : 1;
    const stillOpen = event.open_ended && !event.event_end_time ? ` - ${label(input, 'still_open')}` : '';
    const title = `<title>${escapeXml(`${formatExportDate(event.event_time)} - ${event.title}${stillOpen}`)}</title>`;
    if (event.event_end_time) {
      const endX = Math.max(x(new Date(event.event_end_time).getTime()), startX + 2);
      parts.push(`<rect x="${startX.toFixed(1)}" y="${centerY - 5}" width="${(endX - startX).toFixed(1)}" height="10" rx="3" fill="${color}" fill-opacity="${opacity * 0.6}" stroke="${color}">${title}</rect>`);
    } else if (stillOpen) {
      // A window without a known end runs to the right edge of the plot, its outline dashed
      const width = Math.max(plotRight - startX, 2);
      parts.push(`<rect x="${startX.toFixed(1)}" y="${centerY - 5}" width="${width.toFixed(1)}" height="10" rx="3" fill="${color}" fill-opacity="${opacity * 0.3}" stroke="${color}" stroke-dasharray="4 3">${title}</rect>`);
    } else {
      parts.push(`<circle cx="${startX.toFixed(1)}" cy="${centerY}" r="${event.pinned ? 6 : 4}" fill="${color}" fill-opacity="${opacity}" stroke="#ffffff">${title}</circle>`);
    }
    if (event.pinned || event.source === 'manual') {
      parts.push(`<text x="${(startX + 8).toFixed(1)}" y="${centerY - 8}" fill="${TEXT_COLOR}">${escapeXml(truncate(event.title, MAX_LABEL_CHARS))}</text>`);
    }
  });
  // Anchors
  if (input.anchors) {
    TIMELINE_ANCHOR_KEYS.forEach((key) => {
      const value = input.anchors?.[key];
      if (!value) return;
      const anchorX = x(new Date(value).getTime()).toFixed(1);
      parts.push(`<line x1="${anchorX}" y1="${PADDING + AXIS_HEIGHT}" x2="${anchorX}" y2="${height - PADDING}" stroke="${TEXT_COLOR}" stroke-dasharray="4 3"/>`);
      parts.push(`<text x="${anchorX}" y="${height - 4}" fill="${TEXT_COLOR}" text-anchor="middle" font-size="10">${escapeXml(label(input, `anchor.${key}`))}</text>`);
    });
  }
  parts.push('</svg>');
  return parts.join('');
};
// endregion

// region HTML (consumed by the built-in HTML to PDF export of the front end)
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
    `<h2>${escapeXml(label(input, 'anchors'))}</h2>`,
    `<table><tbody>${anchorsRows}</tbody></table>`,
    `<h2>${escapeXml(label(input, 'title'))}</h2>`,
    renderTimelineSvg(input),
    `<h2>${escapeXml(label(input, 'events'))}</h2>`,
    input.events.length > 0
      ? `<table><thead><tr>${headers}</tr></thead><tbody>${eventRows}</tbody></table>`
      : `<p>${escapeXml(label(input, 'no_events'))}</p>`,
    '</div>',
  ].join('');
};
// endregion
