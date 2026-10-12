import { describe, expect, it } from 'vitest';
import { derivedHuntInput, derivedHuntName } from '../../../../src/modules/hunt/hunt-derivation';
import { huntSightedIdsByHit } from '../../../../src/modules/hunt/hunt-sightings';
import { HUNT_MAX_SIGMA_RULES, huntRuleKey, sanitizeObservations, sanitizeRuleResults } from '../../../../src/modules/hunt/hunt-utils';
import type { HuntIocResult } from '../../../../src/modules/hunt/huntRun/huntRun-types';

const RULE = 'title: Encoded PowerShell\nlogsource:\n  category: process_creation\ndetection:\n  sel:\n    CommandLine|contains: -enc\n  condition: sel';
const OTHER_RULE = 'title: Rundll32 without arguments\nlogsource:\n  category: process_creation\ndetection:\n  sel:\n    Image|endswith: rundll32.exe\n  condition: sel';

describe('Results per rule of a run', () => {
  it('should keep one result per valid rule key, its hits only when completed and its error only when failed', () => {
    const key = huntRuleKey(RULE);
    const results = sanitizeRuleResults([
      { key, title: 'Encoded PowerShell', status: 'completed', hits_count: 4, truncated: false, error: 'ignored', translated_query: 'index=edr' },
      { key, status: 'completed', hits_count: 9 },
      { key: huntRuleKey(OTHER_RULE), status: 'failed', hits_count: 3 },
      { key: 'not a key', status: 'completed', hits_count: 1 },
    ]);
    expect(results).toHaveLength(2);
    expect(results?.[0]).toMatchObject({ key, title: 'Encoded PowerShell', status: 'completed', hits_count: 4, error: null, translated_query: 'index=edr' });
    expect(results?.[1]).toMatchObject({ key: huntRuleKey(OTHER_RULE), status: 'failed', hits_count: 0, error: 'Unknown error' });
  });

  it('should read a status it does not know as a failure, and bound the results to the rules a hunt can hold', () => {
    const results = sanitizeRuleResults(Array.from({ length: HUNT_MAX_SIGMA_RULES + 5 }, (_, index) => ({
      key: huntRuleKey(`${RULE}\n# ${index}`),
      status: index === 0 ? 'running' : 'completed',
      hits_count: 1,
    })));
    expect(results).toHaveLength(HUNT_MAX_SIGMA_RULES);
    expect(results?.[0].status).toEqual('failed');
    expect(sanitizeRuleResults(undefined)).toBeNull();
  });
});

describe('Observations a connector reports over every hit', () => {
  it('should merge the groups of one value and host, and drop those without hits', () => {
    const observations = sanitizeObservations([
      { key: 'ioc-ip', host: 'ws-042', hits_count: 2, first_seen: '2026-10-05T09:00:00.000Z', last_seen: '2026-10-05T09:30:00.000Z', hit_keys: ['a'.repeat(64)] },
      { key: 'ioc-ip', host: 'ws-042', hits_count: 3, first_seen: '2026-10-05T08:00:00.000Z', last_seen: '2026-10-05T10:00:00.000Z', hit_keys: ['b'.repeat(64)] },
      { key: 'ioc-domain', host: null, hits_count: 1 },
      { key: 'ioc-none', host: 'ws-001', hits_count: 0 },
      { key: 'x'.repeat(300), host: 'ws-001', hits_count: 4 },
    ]);
    expect(observations).toHaveLength(2);
    expect(observations?.[0]).toMatchObject({
      key: 'ioc-ip',
      host: 'ws-042',
      hitsCount: 5,
      firstSeen: '2026-10-05T08:00:00.000Z',
      lastSeen: '2026-10-05T10:00:00.000Z',
    });
    expect(observations?.[0].hitKeys).toEqual(['a'.repeat(64), 'b'.repeat(64)]);
    // A group without keys does not identify its hits
    expect(observations?.[1]).toMatchObject({ key: 'ioc-domain', host: null, hitsCount: 1, hitKeys: null });
    expect(sanitizeObservations(undefined)).toBeNull();
  });

  it('should keep the most observed groups first, at most the given number', () => {
    const observations = sanitizeObservations([
      { key: 'ioc-1', host: 'a', hits_count: 1 },
      { key: 'ioc-2', host: 'a', hits_count: 7 },
      { key: 'ioc-3', host: 'a', hits_count: 3 },
    ], 2);
    expect(observations?.map((observation) => observation.key)).toEqual(['ioc-2', 'ioc-3']);
  });
});

describe('Objects a hit was sighted on', () => {
  const result = (key: string, sourceIds: string[], value = '10.0.0.1') => ({ key, source_ids: sourceIds, value, observable_type: 'IPv4-Addr', verdict: 'seen' } as unknown as HuntIocResult);

  it('should give the hits of an indicator hunt the intel of the values they matched, or the observable of a pasted value', () => {
    const [first, second] = ['a', 'b'].map((digit) => digit.repeat(64));
    const byHit = huntSightedIdsByHit({ hunt_type: 'indicators' } as never, [first, second], {
      iocResults: [result('ioc-intel', ['indicator-1']), result('ioc-pasted', [], '10.0.0.2')],
      iocKeysByHit: new Map([[first, ['ioc-intel']], [second, ['ioc-pasted']]]),
    });
    expect(byHit.get(first)).toEqual(['indicator-1']);
    expect(byHit.get(second)?.[0]).toMatch(/^ipv4-addr--/);
  });

  it('should give every hit of a telemetry hunt the objects its sightings name', () => {
    const key = 'c'.repeat(64);
    const byHit = huntSightedIdsByHit({ hunt_type: 'telemetry' } as never, [key], { telemetryTargetIds: ['technique-1', 'indicator-2'] });
    expect(byHit.get(key)).toEqual(['technique-1', 'indicator-2']);
    expect(huntSightedIdsByHit({ hunt_type: 'telemetry' } as never, [key], {}).size).toEqual(0);
  });
});

describe('Hunt a playbook derives from an element', () => {
  const report = { id: 'report-1', name: 'APT report', entity_type: 'Report', relation: 'self' };
  const base = {
    entity: report,
    suggested_type: 'telemetry',
    sources: [report],
    targets: [{ id: 'intrusion-set-1', name: 'APT', entity_type: 'Intrusion-Set', relation: 'targets' }],
    elements: [],
    elements_truncated: false,
    unsupported_count: 0,
    techniques: [{ id: 'technique-1', name: 'PowerShell', entity_type: 'Attack-Pattern', x_mitre_id: 'T1059.001' }],
    rules: [],
    rules_truncated: false,
  };
  const rule = (id: string, pattern: string, patternType = 'sigma') => ({ id, name: id, entity_type: 'Indicator', pattern_type: patternType, pattern, technique_ids: ['technique-2'], pinned: false });

  it('should look for the values of the element, taking it as the source of the hunt', () => {
    const input = derivedHuntInput({ ...base, suggested_type: 'indicators' } as never);
    expect(input).toMatchObject({
      name: derivedHuntName('APT report'),
      hunt_type: 'indicators',
      huntTargets: ['intrusion-set-1'],
      huntTechniques: ['technique-1'],
      huntSources: ['report-1'],
    });
  });

  it('should run every Sigma rule of the element, else its first native rule, and give up without anything to look for', () => {
    const input = derivedHuntInput({ ...base, rules: [rule('rule-1', RULE), rule('rule-2', OTHER_RULE), rule('rule-3', 'index=edr', 'spl')] } as never);
    expect(input).toMatchObject({ hunt_type: 'telemetry', sigma_rules: [RULE, OTHER_RULE], huntSources: ['rule-1', 'rule-2'] });
    expect(input?.huntTechniques).toEqual(['technique-2', 'technique-1']);
    const native = derivedHuntInput({ ...base, rules: [rule('rule-3', 'index=edr', 'spl')] } as never);
    expect(native?.native_queries).toEqual([{ platform: 'splunk', language: 'spl', query: 'index=edr' }]);
    expect(derivedHuntInput(base as never)).toBeNull();
    expect(derivedHuntName('x'.repeat(400))).toHaveLength(250);
  });
});
