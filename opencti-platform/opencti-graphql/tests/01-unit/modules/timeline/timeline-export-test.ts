import { describe, expect, it } from 'vitest';
import {
  csvCell,
  escapeXml,
  formatExportDate,
  layoutExportAnchorLabels,
  layoutExportLane,
  layoutExportRows,
  renderTimelineCsv,
  renderTimelineHtml,
  renderTimelineSvg,
  TIMELINE_EXPORT_LANE_ORDER,
  type TimelineExportEvent,
  type TimelineExportInput,
} from '../../../../src/modules/timeline/timeline-export';
import { TIMELINE_LANES } from '../../../../src/modules/timeline/timeline-types';

const input: TimelineExportInput = {
  containerName: 'Ransomware <case>',
  containerType: 'Case-Incident',
  generatedAt: '2026-04-01T10:30:00.000Z',
  anchors: {
    first_adversary_activity: '2026-03-01T00:00:00.000Z',
    first_detection: '2026-03-03T00:00:00.000Z',
    first_response: null,
    containment: '2026-03-05T00:00:00.000Z',
    closure: null,
    computed_at: '2026-04-01T00:00:00.000Z',
    changed_at: '2026-04-01T00:00:00.000Z',
  },
  events: [
    { id: 'e1', lane: 'adversary', kind: 'technique_used', event_time: '2026-03-01T00:00:00.000Z', event_end_time: '2026-03-02T00:00:00.000Z', precision: 'exact', title: 'Phishing, "spear"', source: 'derived', pinned: false, hidden: false, element_name: 'Phishing', element_type: 'Attack-Pattern' },
    { id: 'e2', lane: 'custom', kind: 'containment', event_time: '2026-03-05T00:00:00.000Z', precision: 'hour', title: '=HYPERLINK("x")', source: 'manual', pinned: true, hidden: false, annotation: 'Hosts isolated' },
  ],
};

describe('Timeline exports', () => {
  it('should escape CSV cells and neutralize formulas', () => {
    expect(csvCell('plain')).toEqual('plain');
    expect(csvCell('a,b')).toEqual('"a,b"');
    expect(csvCell('say "hi"')).toEqual('"say ""hi"""');
    expect(csvCell('=1+1')).toEqual('\'=1+1');
    expect(csvCell('@cmd')).toEqual('\'@cmd');
    expect(csvCell(null)).toEqual('');
    expect(csvCell(true)).toEqual('true');
  });

  it('should render one CSV line per event with a stable header', () => {
    const csv = renderTimelineCsv(input);
    const lines = csv.trim().split('\r\n');
    expect(lines[0]).toEqual('time,end_time,lane,kind,precision,title,element,element_type,source,pinned,hidden,annotation,description');
    expect(lines).toHaveLength(3);
    expect(lines[1]).toContain('"Phishing, ""spear"""');
    expect(lines[2]).toContain('"\'=HYPERLINK(""x"")"');
  });

  it('should render an SVG with lanes, events, labels and anchors', () => {
    const svg = renderTimelineSvg({ ...input, labels: { 'lane.adversary': 'Adversaire' } });
    expect(svg.startsWith('<svg xmlns="http://www.w3.org/2000/svg"')).toBe(true);
    expect(svg).toContain('Adversaire');
    expect(svg).toContain('<rect'); // window of the technique
    expect(svg).toContain('<circle'); // point event
    expect(svg).toContain('First adversary activity');
    expect(svg).toContain('stroke-dasharray');
    expect(svg).toContain('Custom'); // the custom lane is shown because a manual event uses it
    expect(svg.endsWith('</svg>')).toBe(true);
  });

  it('should render an empty SVG when there is nothing to show', () => {
    const svg = renderTimelineSvg({ ...input, events: [], anchors: null });
    expect(svg).toContain('No event');
    expect(svg).not.toContain('Custom');
  });

  it('should draw every lane from top to bottom in the order of the timeline view', () => {
    expect([...TIMELINE_EXPORT_LANE_ORDER].sort()).toEqual([...TIMELINE_LANES].sort());
    const svg = renderTimelineSvg(input);
    const positions = ['Adversary', 'Detection', 'Response', 'Evidence', 'Knowledge', 'Custom'].map((name) => svg.indexOf(`>${name}</text>`));
    expect(positions.every((position) => position >= 0)).toBe(true);
    expect([...positions].sort((a, b) => a - b)).toEqual(positions);
  });

  it('should render the lanes selected in the view only, empty ones included', () => {
    const laneLabels = (svg: string) => ['Adversary', 'Detection', 'Response', 'Evidence', 'Knowledge', 'Custom'].filter((name) => svg.includes(`>${name}</text>`));
    expect(laneLabels(renderTimelineSvg(input))).toEqual(['Adversary', 'Detection', 'Response', 'Evidence', 'Knowledge', 'Custom']);
    const filtered = renderTimelineSvg({ ...input, events: input.events.filter((event) => event.lane === 'adversary'), lanes: ['adversary', 'response'] });
    expect(laneLabels(filtered)).toEqual(['Adversary', 'Response']);
    // A selected lane without events is still drawn, the other lanes are not
    const empty = renderTimelineSvg({ ...input, events: [], anchors: null, lanes: ['detection'] });
    expect(laneLabels(empty)).toEqual(['Detection']);
  });

  it('should render an escaped HTML document for the PDF export', () => {
    const html = renderTimelineHtml(input);
    expect(html).toContain('<h1>Timeline - Ransomware &lt;case&gt;</h1>');
    expect(html).toContain('<table>');
    expect(html).toContain('<svg');
    expect(html).toContain('Hosts isolated');
    expect(html).toContain('2026-03-05 00:00 UTC');
    expect(html).not.toContain('<case>');
  });

  it('should put the drawing first in the HTML of the PDF and start the tables on the next page', () => {
    const html = renderTimelineHtml(input);
    const drawing = html.indexOf('<svg');
    const anchors = html.indexOf('<h2 class="pdf-pagebreak-before">Anchors</h2>');
    expect(drawing).toBeGreaterThan(html.indexOf('<h1>'));
    expect(anchors).toBeGreaterThan(html.indexOf('</svg>'));
    expect(html.indexOf('<h2>Events</h2>')).toBeGreaterThan(anchors);
  });

  it('should draw a window without a known end to the right edge and say it is still open', () => {
    const open = { id: 'e3', lane: 'detection' as const, kind: 'hunt_run', event_time: '2026-03-04T00:00:00.000Z', event_end_time: null, open_ended: true, precision: 'exact', title: 'Hunt run beacons', source: 'derived', pinned: false, hidden: false };
    const svg = renderTimelineSvg({ ...input, events: [...input.events, open], labels: { still_open: 'Toujours en cours' } });
    const bar = svg.split('<rect').find((part) => part.includes('Hunt run beacons')) as string;
    expect(bar).toContain('stroke-dasharray="4 3"');
    expect(bar).toContain('Hunt run beacons - Toujours en cours');
    const html = renderTimelineHtml({ ...input, events: [open] });
    expect(html).toContain('<td>Still open</td>');
    // A point event without an end stays a point
    expect(renderTimelineSvg({ ...input, events: [{ ...open, open_ended: false }] })).not.toContain('Still open');
  });

  it('should draw the global first and last seen of an entity lighter, with a legend entry', () => {
    const context = {
      id: 'e4',
      lane: 'adversary' as const,
      kind: 'malware_seen',
      rule_id: 'entity-first-last-seen',
      event_time: '2026-01-01T00:00:00.000Z',
      event_end_time: '2026-03-10T00:00:00.000Z',
      precision: 'exact',
      title: 'Malware Emotet active',
      source: 'derived',
      pinned: false,
      hidden: false,
    };
    const svg = renderTimelineSvg({ ...input, events: [...input.events, context], labels: { context_window: 'Contexte' } });
    const bar = svg.split('<rect').find((part) => part.includes('Malware Emotet active')) as string;
    expect(bar).toContain('fill-opacity="0.12"');
    expect(svg).toContain('data-legend="context_window"');
    expect(svg).toContain('>Contexte</text>');
    // The first seen of the incident itself is its own activity: drawn like the others, no legend
    const incident = renderTimelineSvg({ ...input, events: [...input.events, { ...context, kind: 'incident_seen', title: 'Incident active' }] });
    expect(incident.split('<rect').find((part) => part.includes('Incident active'))).not.toContain('fill-opacity="0.12"');
    expect(incident).not.toContain('data-legend');
    expect(renderTimelineSvg(input)).not.toContain('data-legend');
  });

  it('should format dates and escape XML', () => {
    expect(formatExportDate('2026-03-05T07:08:00.000Z')).toEqual('2026-03-05 07:08 UTC');
    expect(formatExportDate(null)).toEqual('');
    expect(escapeXml('<a href="x">&\'</a>')).toEqual('&lt;a href=&quot;x&quot;&gt;&amp;&#39;&lt;/a&gt;');
  });
});

describe('Timeline export layout', () => {
  const DAY = 86400000;
  const START = Date.parse('2026-03-01T00:00:00.000Z');
  // One pixel per hour from x = 100
  const x = (time: number) => 100 + (time - START) / 3600000;
  const at = (hours: number) => new Date(START + hours * 3600000).toISOString();
  const event = (id: string, hours: number, extra: Partial<TimelineExportEvent> = {}): TimelineExportEvent => ({
    id, lane: 'adversary', kind: 'technique_used', event_time: at(hours), precision: 'exact', title: id, source: 'derived', pinned: false, hidden: false, ...extra,
  });

  it('should spread overlapping spans over rows and reuse a row once it is free', () => {
    const { rows, rowCount } = layoutExportRows([
      { id: 'a', x1: 0, x2: 100 },
      { id: 'b', x1: 50, x2: 150 },
      { id: 'c', x1: 120, x2: 200 },
    ]);
    expect(rowCount).toEqual(2);
    expect(rows.get('a')).toEqual(0);
    expect(rows.get('b')).toEqual(1);
    expect(rows.get('c')).toEqual(0);
  });

  it('should draw overlapping windows of a lane on different rows', () => {
    const layout = layoutExportLane('adversary', [
      event('Phishing', 0, { event_end_time: at(48) }),
      event('Lateral movement', 24, { event_end_time: at(72) }),
      event('Exfiltration', 100, { event_end_time: at(120) }),
    ], x, 1000);
    const rowOf = (id: string) => layout.items.find((item) => item.id === id)?.row;
    expect(layout.rowCount).toEqual(2);
    expect(rowOf('Phishing')).not.toEqual(rowOf('Lateral movement'));
    expect(rowOf('Exfiltration')).toEqual(0);
  });

  it('should group events too close to be told apart into one count bubble', () => {
    const layout = layoutExportLane('detection', [event('a', 10), event('b', 11), event('c', 12), event('far', 200)], x, 1000);
    const bubble = layout.items.find((item) => item.type === 'bubble');
    expect(bubble?.type === 'bubble' && bubble.events.map((e) => e.id)).toEqual(['a', 'b', 'c']);
    expect(layout.items.filter((item) => item.type === 'point').map((item) => item.id)).toEqual(['far']);
  });

  it('should keep the labelled events (pinned or milestones) apart from each other', () => {
    const layout = layoutExportLane('response', [
      event('Mail server isolated', 10, { pinned: true }),
      event('Containment confirmed', 12, { source: 'manual' }),
    ], x, 1000);
    expect(layout.items.every((item) => item.type === 'point' && item.labelled)).toBe(true);
    expect(new Set(layout.items.map((item) => item.row)).size).toEqual(2);
  });

  it('should group the items beyond the last row of a lane into count bubbles', () => {
    const windows = Array.from({ length: 10 }, (_, index) => event(`w${index}`, index, { event_end_time: at(100) }));
    const layout = layoutExportLane('adversary', windows, x, 1000);
    expect(layout.rowCount).toEqual(6);
    expect(Math.max(...layout.items.map((item) => item.row))).toEqual(5);
    const bubbles = layout.items.filter((item) => item.type === 'bubble');
    expect(bubbles).toHaveLength(1);
    expect(bubbles[0].row).toEqual(5);
    // Every event is still drawn, as a window or inside a bubble
    const drawn = layout.items.flatMap((item) => (item.type === 'bubble' ? item.events.map((e) => e.id) : [item.id]));
    expect(drawn.sort()).toEqual(windows.map((w) => w.id).sort());
  });

  it('should stagger the labels of headline dates of the same day and keep them inside the plot', () => {
    const labels = layoutExportAnchorLabels([
      { key: 'first_detection', x: 500, label: 'First detection' },
      { key: 'first_response', x: 502, label: 'First response' },
      { key: 'closure', x: 1195, label: 'Closure' },
    ], 156, 1184);
    const byKey = Object.fromEntries(labels.map((anchor) => [anchor.key, anchor]));
    expect(byKey.first_detection.row).not.toEqual(byKey.first_response.row);
    expect(byKey.closure.row).toEqual(0);
    // A label near the edge is moved inside the plot while its line stays on the date
    expect(byKey.closure.anchorX).toEqual(1195);
    expect(byKey.closure.x + ('Closure'.length * 5.6) / 2).toBeLessThanOrEqual(1184.001);
  });

  it('should give the lanes and the headline labels the height they need and align the edge dates inside the image', () => {
    const anchors = {
      ...(input.anchors as NonNullable<TimelineExportInput['anchors']>),
      first_adversary_activity: at(0),
      first_detection: at(1),
      first_response: at(2),
      containment: at(3),
      closure: at(4),
    };
    const crowded = renderTimelineSvg({
      ...input,
      anchors,
      events: Array.from({ length: 4 }, (_, index) => event(`w${index}`, index, { event_end_time: at(10 * DAY / 3600000) })),
      lanes: ['adversary'],
    });
    const single = renderTimelineSvg({ ...input, anchors: null, events: [event('alone', 0)], lanes: ['adversary'] });
    const heightOf = (svg: string) => Number(/height="(\d+(\.\d+)?)"/.exec(svg)?.[1]);
    expect(heightOf(crowded)).toBeGreaterThan(heightOf(single) + 3 * 18);
    const tickAnchors = Array.from(crowded.matchAll(/fill="#494a50" text-anchor="(start|middle|end)"/g)).map((match) => match[1]);
    expect(tickAnchors[0]).toEqual('start');
    expect(tickAnchors[tickAnchors.length - 1]).toEqual('end');
    // Five headline dates within four hours: their labels sit on more than one row
    const labelRows = new Set(Array.from(crowded.matchAll(/<text x="[\d.]+" y="([\d.]+)" fill="#18191b" text-anchor="middle" font-size="10">/g)).map((match) => match[1]));
    expect(labelRows.size).toBeGreaterThan(1);
  });
});
