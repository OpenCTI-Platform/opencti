import { describe, expect, it } from 'vitest';
import {
  csvCell,
  escapeXml,
  formatExportDate,
  renderTimelineCsv,
  renderTimelineHtml,
  renderTimelineSvg,
  TIMELINE_EXPORT_LANE_ORDER,
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

  it('should format dates and escape XML', () => {
    expect(formatExportDate('2026-03-05T07:08:00.000Z')).toEqual('2026-03-05 07:08 UTC');
    expect(formatExportDate(null)).toEqual('');
    expect(escapeXml('<a href="x">&\'</a>')).toEqual('&lt;a href=&quot;x&quot;&gt;&amp;&#39;&lt;/a&gt;');
  });
});
