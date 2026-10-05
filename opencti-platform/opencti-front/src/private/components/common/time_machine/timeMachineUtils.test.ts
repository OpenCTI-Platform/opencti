import { describe, expect, it } from 'vitest';
import { createIntl } from 'react-intl';
import {
  actionLabel,
  attributeOperation,
  carriesAsOfDate,
  CHANGES_SECTION_AS_OF,
  CHANGES_SECTION_COMPARE,
  changesSearch,
  clampDate,
  comparePeriodSearch,
  diffSummaryMeasures,
  entityChangesPath,
  entityDiffToCsv,
  entityDiffToHtml,
  entityDiffToJson,
  type EntityDiffData,
  escapeCsvCell,
  escapeHtml,
  exportFileName,
  formatDuration,
  isValidDate,
  landscapeDiffToCsv,
  landscapeDiffToHtml,
  countLabel,
  type LandscapeDiffData,
  landscapeFailureReason,
  LANDSCAPE_POLL_INTERVAL_MS,
  landscapePollRetryDelay,
  landscapeGroupBuckets,
  landscapeGroupTitle,
  presetLabel,
  presetRange,
  sinceLastVisitSearch,
  TIME_MACHINE_PRESETS,
  valuesToText,
  toComparableRange,
  widgetDefaultRange,
} from './timeMachineUtils';

const t = (message: string) => message;
const intl = createIntl({ locale: 'en', messages: {}, onError: () => {} });
const tWithValues = (message: string, opts?: { values?: Record<string, string | number> }) => intl.formatMessage({ id: message, defaultMessage: message }, opts?.values);
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
      standard_id: 'intrusion-set--4e7c3b44-8c39-5f3d-9b6e-1b2c3d4e5f60',
      entity_type: 'Intrusion-Set',
      name: '=HYPERLINK("http://evil")',
      created_in_period: false,
      revoked_in_period: false,
      attributes_changed: 2,
      relationships_added: 8,
      relationships_removed: 1,
      relationships_revoked: 0,
      relationships_confidence_changed: 3,
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
    // The operation of each attribute row is the one the table shows
    expect(lines[2]).toBe('Attributes,aliases,Aliases,Added,,"Fancy Bear, Sofacy",,');
    expect(lines[3]).toBe('Relationships,uses,X-Agent,Added,,75,2026-09-01T00:00:00.000Z,connector');
  });

  it('writes a transition from or to an unset confidence or score like on screen', () => {
    const summary = { ...entityDiff.summary, confidence_before: null, confidence_after: 75, score_before: 40, score_after: null };
    const html = entityDiffToHtml({ ...entityDiff, summary }, tWithValues, formatDate);
    expect(html).toContain('<td>Confidence</td><td>Not set -&gt; 75</td>');
    expect(html).toContain('<td>Score</td><td>40 -&gt; Not set</td>');
  });

  it('builds an escaped HTML document for the PDF export', () => {
    const html = entityDiffToHtml(entityDiff, tWithValues, formatDate);
    expect(html).toContain('<h1>APT &lt;28&gt;</h1>');
    expect(html).toContain('<p>Changes between 2026-07-01 and 2026-10-01</p>');
    expect(html).toContain('<td>Confidence</td><td>50 -&gt; 80</td>');
    expect(html).toContain('<td>Score</td><td>-</td>');
    expect(html).toContain('Old victim (deleted)');
    expect(html).not.toContain('Contained objects');
  });

  it('states when there is no change', () => {
    const html = entityDiffToHtml({ ...entityDiff, attributes: [], relationships: [] }, tWithValues, formatDate);
    expect(html.match(/No changes/g)).toHaveLength(2);
  });
});

describe('landscape diff exports', () => {
  it('builds one CSV row per changed entity and neutralizes formulas', () => {
    const lines = landscapeDiffToCsv(landscapeDiff, t).split('\n');
    expect(lines).toHaveLength(2);
    expect(lines[0].split(',')[2]).toBe('Standard STIX ID');
    expect(lines[0].split(',')[9]).toBe('Confidence changes on relationships');
    expect(lines[1]).toBe('"\'=HYPERLINK(""http://evil"")",Intrusion-Set,intrusion-set--4e7c3b44-8c39-5f3d-9b6e-1b2c3d4e5f60,false,false,2,8,1,0,3,50 -> 80,,21');
  });

  it('builds the HTML report with the non-empty aggregates only', () => {
    const html = landscapeDiffToHtml(landscapeDiff, tWithValues, formatDate);
    expect(html).toContain('<h1>Landscape changes</h1>');
    expect(html).toContain('<p>Changes between 2026-07-01 and 2026-10-01</p>');
    expect(html).toContain('<td>Entity types</td><td>entity_Intrusion-Set</td>');
    expect(html).toContain('<h3>New techniques by tactic</h3>');
    expect(html).toContain('<td>Phishing</td><td>Attack-Pattern</td><td>2</td>');
    expect(html).toContain('<h3>New victims by country</h3>');
    expect(html).not.toContain('New victims by sector');
    expect(html).not.toContain('New malware');
    expect(html).toContain('<h2>Top changed entities</h2>');
  });

  it('handles a diff without aggregates nor entities', () => {
    const html = landscapeDiffToHtml({ ...landscapeDiff, aggregates: null, entities: [] }, tWithValues, formatDate);
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

describe('Changes tab links', () => {
  it('ties a link to the as-of view only when it carries a valid date', () => {
    expect(carriesAsOfDate(new URLSearchParams({ asOf: '2026-07-01T00:00:00.000Z' }))).toBe(true);
    expect(carriesAsOfDate(new URLSearchParams({ asOf: 'not a date' }))).toBe(false);
    expect(carriesAsOfDate(new URLSearchParams({ from: '2026-07-01T00:00:00.000Z' }))).toBe(false);
  });

  it('opens the comparison of the entity on the period, or the page of entities without a Changes tab', () => {
    const period = { from: '2026-07-01T00:00:00.000Z', to: '2026-10-01T00:00:00.000Z' };
    const path = entityChangesPath('/dashboard/threats/intrusion_sets', 'id-1', 'Intrusion-Set', period);
    expect(path.startsWith('/dashboard/threats/intrusion_sets/id-1/changes?')).toBe(true);
    expect(new URLSearchParams(path.split('?')[1]).get('section')).toBe(CHANGES_SECTION_COMPARE);
    expect(entityChangesPath('/dashboard/analyses/reports', 'id-2', 'Report', period).startsWith('/dashboard/analyses/reports/id-2/changes?')).toBe(true);
    expect(entityChangesPath('/dashboard/analyses/opinions', 'id-3', 'Opinion', period)).toBe('/dashboard/analyses/opinions/id-3');
  });

  it('builds the search of a section with its own parameters', () => {
    expect(changesSearch(CHANGES_SECTION_AS_OF)).toBe('section=as-of');
    const search = new URLSearchParams(comparePeriodSearch({ from: '2026-07-01T00:00:00.000Z', to: '2026-10-01T00:00:00.000Z' }));
    expect(search.get('section')).toBe(CHANGES_SECTION_COMPARE);
    expect(search.get('from')).toBe('2026-07-01T00:00:00.000Z');
    expect(search.get('to')).toBe('2026-10-01T00:00:00.000Z');
  });
});

describe('Landscape changes grouping', () => {
  const grouped = (groupBy: string, groups: Array<{ key: string; label: string; count: number }>): LandscapeDiffData => ({
    ...landscapeDiff,
    group_by: groupBy,
    aggregates: landscapeDiff.aggregates ? { ...landscapeDiff.aggregates, groups } : null,
  });
  const translate = (message: string) => `T(${message})`;

  it('titles the breakdown chosen with Group by', () => {
    expect(landscapeGroupTitle('entity_type')).toBe('Changed entities by entity type');
    expect(landscapeGroupTitle('relationship_type')).toBe('New relationships by type');
    expect(landscapeGroupTitle('tactic')).toBe('New techniques by tactic');
    expect(landscapeGroupTitle(null)).toBe('Changed entities by entity type');
  });

  it('translates the entity and relationship types of the breakdown, not the tactics', () => {
    const buckets = [{ key: 'k', label: 'Intrusion-Set', count: 2 }];
    expect(landscapeGroupBuckets(grouped('entity_type', buckets), translate)[0].label).toBe('T(entity_Intrusion-Set)');
    expect(landscapeGroupBuckets(grouped('relationship_type', [{ key: 'uses', label: 'uses', count: 1 }]), translate)[0].label).toBe('T(relationship_uses)');
    expect(landscapeGroupBuckets(grouped('tactic', [{ key: 'execution', label: 'Execution', count: 1 }]), translate)[0].label).toBe('Execution');
    expect(landscapeGroupBuckets({ ...landscapeDiff, aggregates: null }, translate)).toEqual([]);
  });

  it('puts the chosen breakdown first in the PDF and does not repeat it', () => {
    const html = landscapeDiffToHtml(grouped('tactic', [{ key: 'initial-access', label: 'Initial Access', count: 2 }]), t, (date) => date);
    expect(html.indexOf('New techniques by tactic')).toBeLessThan(html.indexOf('New techniques<'));
    expect(html.split('New techniques by tactic').length - 1).toBe(1);
    const byType = landscapeDiffToHtml(grouped('entity_type', [{ key: 'Intrusion-Set', label: 'Intrusion-Set', count: 3 }]), t, (date) => date);
    expect(byType).toContain('Changed entities by entity type');
    expect(byType).toContain('New techniques by tactic');
    expect(byType).toContain('New relationships by type');
  });
});

describe('Counts and widget periods', () => {
  const t = tWithValues;

  it('should write a count with its singular or plural unit', () => {
    expect(countLabel('new_relationships', 1, t)).toEqual('1 new relationship');
    expect(countLabel('new_relationships', 3, t)).toEqual('3 new relationships');
    expect(countLabel('updates', 1, t)).toEqual('1 update');
    expect(countLabel('new_container_objects', 2, t)).toEqual('2 new objects');
    expect(countLabel('attributes_changed', 0, t)).toEqual('0 attributes changed');
  });

  it('should write durations in the largest readable unit', () => {
    const format = (value: number, unit: string) => `${value} ${unit}`;
    expect(formatDuration(40_400, format)).toEqual('40 second');
    expect(formatDuration(185_000, format)).toEqual('3 minute');
    expect(formatDuration(90 * 60_000, format)).toEqual('1.5 hour');
    expect(formatDuration(-5_000, format)).toEqual('0 second');
  });

  it('should keep a comparable period only, its end moved back to now', () => {
    const now = new Date('2026-10-05T12:00:00.000Z');
    expect(toComparableRange('2026-10-01T00:00:00.000Z', '2026-10-02T00:00:00.000Z', now)).toEqual({ from: '2026-10-01T00:00:00.000Z', to: '2026-10-02T00:00:00.000Z' });
    expect(toComparableRange('2026-10-01T00:00:00.000Z', '2026-11-01T00:00:00.000Z', now)).toEqual({ from: '2026-10-01T00:00:00.000Z', to: '2026-10-05T12:00:00.000Z' });
    // Equal, reversed, future-only and unreadable periods are empty
    expect(toComparableRange('2026-10-01T00:00:00.000Z', '2026-10-01T00:00:00.000Z', now)).toBeNull();
    expect(toComparableRange('2026-10-02T00:00:00.000Z', '2026-10-01T00:00:00.000Z', now)).toBeNull();
    expect(toComparableRange('2026-10-06T00:00:00.000Z', '2026-10-07T00:00:00.000Z', now)).toBeNull();
    expect(toComparableRange('not-a-date', '2026-10-02T00:00:00.000Z', now)).toBeNull();
    expect(toComparableRange('2026-10-01T00:00:00.000Z', null, now)).toBeNull();
  });

  it('should keep the default widget period stable for a whole minute, ending at its start', () => {
    const early = widgetDefaultRange(new Date('2026-10-03T22:40:05.123Z'));
    const late = widgetDefaultRange(new Date('2026-10-03T22:40:59.999Z'));
    expect(early).toEqual(late);
    expect(early.to).toEqual('2026-10-03T22:40:00.000Z');
    expect(early.from).toEqual('2026-09-03T22:40:00.000Z');
    expect(widgetDefaultRange(new Date('2026-10-03T22:41:00.000Z')).to).toEqual('2026-10-03T22:41:00.000Z');
  });
});

describe('Comparison summary and rows', () => {
  const summary = {
    attributes_changed: 2,
    relationships_added: 0,
    relationships_removed: 0,
    relationships_revoked: 1,
    relationships_confidence_changed: 0,
    container_objects_added: 0,
    container_objects_removed: 0,
    confidence_before: 50,
    confidence_after: 80,
    score_before: null,
    score_after: null,
  };

  it('should flag the measures that changed and keep contained objects for containers only', () => {
    const changed = (isContainer: boolean) => diffSummaryMeasures(summary, isContainer).filter((measure) => measure.changed).map((measure) => measure.key);
    expect(changed(false)).toEqual(['attributes_changed', 'relationships_revoked', 'confidence']);
    const unchanged = diffSummaryMeasures(summary, false).filter((measure) => !measure.changed).map((measure) => measure.key);
    expect(unchanged).toEqual(['relationships_added', 'relationships_removed', 'score', 'relationships_confidence_changed']);
    expect(diffSummaryMeasures(summary, true).map((measure) => measure.key)).toContain('container_objects');
    // A score set during the period is a change, even from no value
    expect(diffSummaryMeasures({ ...summary, score_after: 40 }, false).find((measure) => measure.key === 'score')?.changed).toBe(true);
  });

  it('should name the operation of an attribute row', () => {
    expect(attributeOperation([], ['a'])).toEqual('added');
    expect(attributeOperation(['a'], [])).toEqual('removed');
    expect(attributeOperation(['a'], ['b'])).toEqual('changed');
  });

  it('should open the comparison since the last visit with its preset', () => {
    const search = new URLSearchParams(sinceLastVisitSearch('2026-09-01T10:00:00.000Z', new Date('2026-10-04T12:00:00.000Z')));
    expect(search.get('section')).toEqual('compare');
    expect(search.get('from')).toEqual('2026-09-01T10:00:00.000Z');
    expect(search.get('to')).toEqual('2026-10-04T12:00:00.000Z');
    expect(search.get('lastVisit')).toEqual('2026-09-01T10:00:00.000Z');
  });
});

describe('Landscape changes failures', () => {
  it('should explain the failures an analyst can act upon and never show the raw message', () => {
    expect(landscapeFailureReason('Landscape diff computation was interrupted'))
      .toEqual('The computation stopped before its end, for example because the platform restarted.');
    expect(landscapeFailureReason('Access to the knowledge of this landscape diff changed, it must be computed again'))
      .toEqual('Access to part of this knowledge changed since the computation, so its result can no longer be shown.');
    expect(landscapeFailureReason('Cannot read properties of undefined')).toEqual('An unexpected error stopped the computation.');
    expect(landscapeFailureReason(null)).toEqual('An unexpected error stopped the computation.');
  });

  it('should read a running landscape diff again after a failed read, less and less often', () => {
    expect(landscapePollRetryDelay(1)).toEqual(2 * LANDSCAPE_POLL_INTERVAL_MS);
    expect(landscapePollRetryDelay(2)).toEqual(4 * LANDSCAPE_POLL_INTERVAL_MS);
    expect(landscapePollRetryDelay(3)).toEqual(8 * LANDSCAPE_POLL_INTERVAL_MS);
    // Capped, so a long outage is still followed by a read within half a minute
    expect(landscapePollRetryDelay(20)).toEqual(30000);
  });
});
