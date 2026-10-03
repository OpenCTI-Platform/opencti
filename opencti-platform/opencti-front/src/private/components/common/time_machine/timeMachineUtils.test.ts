import { describe, expect, it } from 'vitest';
import {
  actionLabel,
  clampDate,
  entityDiffToCsv,
  entityDiffToHtml,
  entityDiffToJson,
  type EntityDiffData,
  escapeCsvCell,
  escapeHtml,
  exportFileName,
  isValidDate,
  landscapeDiffToCsv,
  landscapeDiffToHtml,
  type LandscapeDiffData,
  presetLabel,
  presetRange,
  TIME_MACHINE_PRESETS,
  valuesToText,
} from './timeMachineUtils';

const t = (message: string) => message;
const formatDate = (date: string) => date.substring(0, 10);

const value = (display: string, extra: Partial<{ deleted: boolean; restricted: boolean }> = {}) => ({
  raw: display,
  display,
  deleted: extra.deleted ?? false,
  restricted: extra.restricted ?? false,
});

const entityDiff: EntityDiffData = {
  entity_id: 'intrusion-set-id',
  entity_type: 'Intrusion-Set',
  representative: 'APT <28>',
  from: '2026-07-01T00:00:00.000Z',
  to: '2026-10-01T00:00:00.000Z',
  summary: {
    attributes_changed: 2,
    relationships_added: 1,
    relationships_removed: 1,
    relationships_revoked: 0,
    relationships_confidence_changed: 0,
    container_objects_added: 0,
    container_objects_removed: 0,
    confidence_before: 50,
    confidence_after: 80,
    score_before: null,
    score_after: null,
  },
  attributes: [
    { key: 'description', label: 'Description', before: [value('old')], after: [value('new, "quoted"')], changed_at: '2026-08-01T10:00:00.000Z', changed_by: 'admin' },
    { key: 'aliases', label: 'Aliases', before: [], after: [value('Fancy Bear'), value('Sofacy')], changed_at: null, changed_by: null },
  ],
  relationships: [
    { relationship_type: 'uses', action: 'added', at: '2026-09-01T00:00:00.000Z', target_name: 'X-Agent', target_type: 'Malware', target_deleted: false, confidence_before: null, confidence_after: 75, changed_by: 'connector' },
    { relationship_type: 'targets', action: 'removed', at: '2026-09-02T00:00:00.000Z', target_name: 'Old victim', target_type: null, target_deleted: true, confidence_before: null, confidence_after: null, changed_by: null },
  ],
  container_objects: [],
};

const landscapeDiff: LandscapeDiffData = {
  from: '2026-07-01T00:00:00.000Z',
  to: '2026-10-01T00:00:00.000Z',
  scope_entity_types: ['Intrusion-Set'],
  aggregates: {
    entities_in_scope: 10,
    entities_changed: 3,
    new_entities: 1,
    new_relationships: 12,
    removed_relationships: 2,
    revocations: 1,
    confidence_changes: 4,
    score_changes: 0,
    new_infrastructure_count: 5,
    new_indicators_count: 7,
    new_relationships_by_type: [{ key: 'uses', label: 'uses', count: 8 }],
    new_techniques_by_tactic: [{ key: 'initial-access', label: 'Initial Access', count: 2 }],
    new_victims_by_sector: [],
    new_victims_by_country: [{ key: 'france', label: 'France', count: 1 }],
    new_victims_by_region: [],
    new_techniques: [{ id: 'attack-pattern-id', entity_type: 'Attack-Pattern', name: 'Phishing', count: 2 }],
    new_malware: [],
    new_tools: [],
    new_infrastructure: [],
  },
  entities: [
    {
      entity_id: 'intrusion-set-id',
      entity_type: 'Intrusion-Set',
      name: '=HYPERLINK("http://evil")',
      created_in_period: false,
      revoked_in_period: false,
      attributes_changed: 2,
      relationships_added: 8,
      relationships_removed: 1,
      relationships_revoked: 0,
      confidence_before: 50,
      confidence_after: 80,
      score_before: null,
      score_after: null,
      change_score: 21,
    },
  ],
};

describe('presetRange', () => {
  const now = new Date('2026-10-03T12:00:00.000Z');

  it('computes rolling windows ending now', () => {
    expect(presetRange('7d', now)).toEqual({ from: '2026-09-26T12:00:00.000Z', to: now.toISOString() });
    expect(presetRange('30d', now).from).toBe('2026-09-03T12:00:00.000Z');
    expect(presetRange('90d', now).from).toBe('2026-07-05T12:00:00.000Z');
    expect(presetRange('365d', now).from).toBe('2025-10-03T12:00:00.000Z');
  });

  it('follows calendar quarters in UTC', () => {
    expect(presetRange('quarter', now)).toEqual({ from: '2026-10-01T00:00:00.000Z', to: now.toISOString() });
    expect(presetRange('previous_quarter', now)).toEqual({ from: '2026-07-01T00:00:00.000Z', to: '2026-10-01T00:00:00.000Z' });
  });

  it('crosses the year boundary for the previous quarter', () => {
    expect(presetRange('previous_quarter', new Date('2026-02-15T08:00:00.000Z'))).toEqual({
      from: '2025-10-01T00:00:00.000Z',
      to: '2026-01-01T00:00:00.000Z',
    });
  });

  it('labels every preset', () => {
    TIME_MACHINE_PRESETS.forEach((preset) => expect(presetLabel(preset)).not.toBe(preset));
  });
});

describe('date helpers', () => {
  it('validates dates', () => {
    expect(isValidDate('2026-10-03T00:00:00.000Z')).toBe(true);
    expect(isValidDate('not a date')).toBe(false);
    expect(isValidDate(null)).toBe(false);
    expect(isValidDate(undefined)).toBe(false);
    expect(isValidDate('')).toBe(false);
  });

  it('clamps slider values', () => {
    expect(clampDate(5, 10, 20)).toBe(10);
    expect(clampDate(25, 10, 20)).toBe(20);
    expect(clampDate(15, 10, 20)).toBe(15);
  });
});

describe('escaping', () => {
  it('neutralizes spreadsheet formulas and quotes separators in CSV cells', () => {
    expect(escapeCsvCell('=SUM(A1)')).toBe('\'=SUM(A1)');
    expect(escapeCsvCell('+1')).toBe('\'+1');
    expect(escapeCsvCell('-1')).toBe('\'-1');
    expect(escapeCsvCell('@cmd')).toBe('\'@cmd');
    expect(escapeCsvCell('\n=cmd')).toBe('"\'\n=cmd"');
    expect(escapeCsvCell('a,b')).toBe('"a,b"');
    expect(escapeCsvCell('say "hi"')).toBe('"say ""hi"""');
    expect(escapeCsvCell('line\nbreak')).toBe('"line\nbreak"');
    expect(escapeCsvCell(null)).toBe('');
    expect(escapeCsvCell(undefined)).toBe('');
    expect(escapeCsvCell(42)).toBe('42');
    expect(escapeCsvCell(false)).toBe('false');
  });

  it('escapes HTML special characters', () => {
    expect(escapeHtml('<script>alert("x") & \'y\'</script>')).toBe('&lt;script&gt;alert(&quot;x&quot;) &amp; &#39;y&#39;&lt;/script&gt;');
    expect(escapeHtml(null)).toBe('');
    expect(escapeHtml(3)).toBe('3');
  });
});

describe('labels and values', () => {
  it('translates known actions and keeps unknown ones', () => {
    expect(actionLabel('confidence_changed', t)).toBe('Confidence changed');
    expect(actionLabel('custom', t)).toBe('custom');
  });

  it('joins displayed values', () => {
    expect(valuesToText([value('a'), value('b')])).toBe('a, b');
    expect(valuesToText([])).toBe('');
  });
});

describe('entity diff exports', () => {
  it('serializes the diff as JSON', () => {
    expect(JSON.parse(entityDiffToJson(entityDiff))).toEqual(entityDiff);
  });

  it('builds one CSV row per change with a header', () => {
    const lines = entityDiffToCsv(entityDiff, t).split('\n');
    expect(lines[0]).toBe('Section,Type,Field or target,Action,Before,After,Date,By');
    expect(lines).toHaveLength(1 + entityDiff.attributes.length + entityDiff.relationships.length);
    expect(lines[1]).toBe('Attributes,description,Description,Changed,old,"new, ""quoted""",2026-08-01T10:00:00.000Z,admin');
    expect(lines[3]).toBe('Relationships,uses,X-Agent,Added,,75,2026-09-01T00:00:00.000Z,connector');
  });

  it('builds an escaped HTML document for the PDF export', () => {
    const html = entityDiffToHtml(entityDiff, t, formatDate);
    expect(html).toContain('<h1>APT &lt;28&gt;</h1>');
    expect(html).toContain('Changes between 2026-07-01 and 2026-10-01');
    expect(html).toContain('<td>Confidence</td><td>50 -&gt; 80</td>');
    expect(html).toContain('<td>Score</td><td>-</td>');
    expect(html).toContain('Old victim (deleted)');
    expect(html).not.toContain('Contained objects');
  });

  it('states when there is no change', () => {
    const html = entityDiffToHtml({ ...entityDiff, attributes: [], relationships: [] }, t, formatDate);
    expect(html.match(/No changes/g)).toHaveLength(2);
  });
});

describe('landscape diff exports', () => {
  it('builds one CSV row per changed entity and neutralizes formulas', () => {
    const lines = landscapeDiffToCsv(landscapeDiff, t).split('\n');
    expect(lines).toHaveLength(2);
    expect(lines[1]).toBe('"\'=HYPERLINK(""http://evil"")",Intrusion-Set,false,false,2,8,1,0,50 -> 80,,21');
  });

  it('builds the HTML report with the non-empty aggregates only', () => {
    const html = landscapeDiffToHtml(landscapeDiff, t, formatDate);
    expect(html).toContain('<h1>Landscape changes</h1>');
    expect(html).toContain('Entity types: Intrusion-Set');
    expect(html).toContain('<h3>New techniques by tactic</h3>');
    expect(html).toContain('<td>Phishing</td><td>Attack-Pattern</td><td>2</td>');
    expect(html).toContain('<h3>New victims by country</h3>');
    expect(html).not.toContain('New victims by sector');
    expect(html).not.toContain('New malware');
    expect(html).toContain('<h2>Top changed entities</h2>');
  });

  it('handles a diff without aggregates nor entities', () => {
    const html = landscapeDiffToHtml({ ...landscapeDiff, aggregates: null, entities: [] }, t, formatDate);
    expect(html).not.toContain('Summary');
    expect(html).not.toContain('Top changed entities');
  });
});

describe('exportFileName', () => {
  it('builds a safe file name with the period', () => {
    expect(exportFileName('APT 28 / diff', '2026-07-01T00:00:00.000Z', '2026-10-01T00:00:00.000Z', 'csv')).toBe('APT_28_diff_2026-07-01_2026-10-01.csv');
  });

  it('keeps unicode letters and falls back when nothing is left', () => {
    expect(exportFileName('Lazarus été', '2026-07-01', '2026-10-01', 'json')).toBe('Lazarus_été_2026-07-01_2026-10-01.json');
    expect(exportFileName('///', '2026-07-01', '2026-10-01', 'pdf')).toBe('diff_2026-07-01_2026-10-01.pdf');
  });
});
