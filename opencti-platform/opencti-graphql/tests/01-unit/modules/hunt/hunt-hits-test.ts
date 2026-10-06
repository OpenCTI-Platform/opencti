import { describe, expect, it } from 'vitest';
import {
  HUNT_DEFAULT_EXPECTED_OBSERVABLES,
  huntExpectedObservables,
  huntHitDates,
  markMatchedEvidence,
  mergeEvidence,
  mergeHits,
  sanitizeEvidence,
  sanitizeHits,
  sha256,
} from '../../../../src/modules/hunt/hunt-utils';
import { extractHitObservables } from '../../../../src/modules/hunt/hunt-hit-observations';
import { buildHuntIncidentContent, HUNT_INCIDENT_RECOMMENDATION, huntIncidentRelatedIds } from '../../../../src/modules/hunt/hunt-incident';
import type { BasicStoreEntityHunt } from '../../../../src/modules/hunt/hunt-types';
import type { BasicStoreEntityHuntRun, HuntHit, HuntHitField } from '../../../../src/modules/hunt/huntRun/huntRun-types';

const COMMAND_LINE = 'powershell.exe -enc SQBFAFgA';
const commandLineHash = sha256(COMMAND_LINE);

const hit = (fields: Partial<HuntHit>): HuntHit => ({
  event_id: null,
  timestamp: null,
  detection: null,
  matched: [],
  host: null,
  user: null,
  process: null,
  ...fields,
});
const matchedField = (field: string, value: string, complete = true): HuntHitField => ({
  field,
  value_hash: sha256(sha256(value)),
  value_preview: value,
  value_complete: complete,
});

describe('Hunt hits sample', () => {
  it('should keep one readable item per hit: the matched field and value, host, user, process, date and event id', () => {
    const [stored] = sanitizeHits([{
      event_id: 'evt-1',
      timestamp: '2026-10-05T10:00:00Z',
      detection: 'rule_powershell_encoded',
      matched: [{ field: 'target.process.command_line', value_hash: commandLineHash, value_preview: COMMAND_LINE }],
      host: 'ws-042.corp.local',
      user: 'CORP\\jdoe',
      process: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
    }]);
    expect(stored).toEqual({
      // The events of one detection are one hit: the detection identifies it
      hit_key: sha256(JSON.stringify(['v1', 'detection', 'rule_powershell_encoded'])),
      event_id: 'evt-1',
      timestamp: '2026-10-05T10:00:00.000Z',
      detection: 'rule_powershell_encoded',
      matched: [{ field: 'target.process.command_line', value_hash: sha256(commandLineHash), value_preview: COMMAND_LINE, value_complete: true }],
      host: 'ws-042.corp.local',
      user: 'CORP\\jdoe',
      process: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
    });
  });

  it('should hash matched values again, mask secrets and mark truncated or masked previews incomplete', () => {
    const secret = 'curl -u admin:S3cretPass https://example.com';
    const [stored] = sanitizeHits([{
      matched: [
        { field: 'target.process.command_line', value_hash: sha256(secret), value_preview: secret },
        { field: 'target.url', value_hash: sha256('https://example.com/a/very/long/path'), value_preview: 'https://example.com/a/ve' },
      ],
      user: 'svc password=Hunter22',
    }]);
    expect(stored.matched[0].value_preview).not.toContain('S3cretPass');
    expect(stored.matched[0].value_complete).toBe(false);
    expect(stored.matched[1].value_complete).toBe(false);
    expect(stored.user).not.toContain('Hunter22');
  });

  it('should drop hits without any value and keep at most the platform cap, in time order', () => {
    const hits = sanitizeHits([
      { timestamp: '2026-10-05T12:00:00Z', host: 'b' },
      {},
      { matched: [] },
      { timestamp: new Date('2026-10-05T11:00:00Z'), host: 'a' },
      { host: 'undated' },
    ], 2);
    expect(hits.map((item) => item.host)).toEqual(['a', 'b']);
    expect(sanitizeHits(null)).toEqual([]);
  });

  it('should merge late hits without doubling an event', () => {
    const stored = sanitizeHits([{ event_id: 'evt-1', timestamp: '2026-10-05T10:00:00Z', host: 'a' }]);
    const merged = mergeHits(stored, sanitizeHits([
      { event_id: 'evt-1', timestamp: '2026-10-05T10:00:00Z', host: 'a' },
      { event_id: 'evt-0', timestamp: '2026-10-05T09:00:00Z', host: 'z' },
    ]));
    expect(merged.map((item) => item.event_id)).toEqual(['evt-0', 'evt-1']);
  });

  it('should date the first and last hit from the reported dates widened by the sample', () => {
    const hits = [hit({ timestamp: '2026-10-05T09:00:00.000Z' }), hit({ timestamp: null }), hit({ timestamp: '2026-10-05T07:00:00.000Z' })];
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

  it('should read the hits_sample a hunt connector sends: matched fields first in the evidence, observables, incident', () => {
    // The shape of the connectors SDK (HuntHitEvidence.model_dump(mode="json")), sent next to its evidence_sample
    const connectorHits = [{
      event_id: 'AAAAAH1xYz',
      timestamp: '2026-10-05T10:00:00Z',
      detection: null,
      matched: [{ field: 'target.process.command_line', value_hash: commandLineHash, value_preview: COMMAND_LINE }],
      host: 'ws-042',
      user: 'jdoe',
      process: 'powershell.exe',
    }];
    const connectorEvidence = [
      { field: 'metadata.log_type', value_hash: sha256('WINEVTLOG'), value_preview: 'WINEVTLOG', count: 28 },
      { field: 'target.process.command_line', value_hash: commandLineHash, value_preview: COMMAND_LINE, count: 3 },
    ];
    const hits = sanitizeHits(connectorHits);
    const evidence = markMatchedEvidence(sanitizeEvidence(connectorEvidence), hits);
    expect(evidence.map((item) => [item.field, item.matched])).toEqual([['target.process.command_line', true], ['metadata.log_type', false]]);
    expect(extractHitObservables(hits[0]).map((observable) => observable.key)).toEqual([`Process:${COMMAND_LINE}`, 'Hostname:ws-042', 'User-Account:jdoe']);
    const hunt = { internal_id: 'hunt-1', name: 'Encoded PowerShell' } as unknown as BasicStoreEntityHunt;
    const run = { internal_id: 'run-1', hits_count: 1, hits_sample: hits } as unknown as BasicStoreEntityHuntRun;
    expect(buildHuntIncidentContent(hunt, run, null, null).description)
      .toContain(`- 2026-10-05T10:00:00.000Z, host ws-042, user jdoe, process powershell.exe, target.process.command_line = ${COMMAND_LINE}`);
  });
});

describe('Observables of a hit', () => {
  it('should extract the host, account and what the complete matched values hold, never a masked or truncated value', () => {
    const observables = extractHitObservables(hit({
      host: 'ws-042',
      user: 'alice',
      matched: [
        matchedField('principal.ip', '10.0.0.4, 2001:db8::1'),
        matchedField('network.dns.questions.name', 'Evil.Example'),
        matchedField('target.url', 'https://evil.example/x'),
        matchedField('target.file.md5', 'D41D8CD98F00B204E9800998ECF8427E'),
        matchedField('target.process.command_line', 'curl https://evil.example/x'),
        matchedField('target.process.file.full_path', 'explorer.exe'),
        matchedField('principal.hostname', 'ws-042'),
        matchedField('target.ip', '10.0.0.5', false),
      ],
    }));
    expect(observables.map((observable) => observable.key)).toEqual([
      'IPv4-Addr:10.0.0.4',
      'IPv6-Addr:2001:db8::1',
      'Domain-Name:evil.example',
      'Url:https://evil.example/x',
      'StixFile:d41d8cd98f00b204e9800998ecf8427e',
      'Process:curl https://evil.example/x',
      'Hostname:ws-042',
      'User-Account:alice',
    ]);
    expect(observables[4].input).toEqual({ StixFile: { hashes: [{ algorithm: 'MD5', hash: 'd41d8cd98f00b204e9800998ecf8427e' }] } });
    expect(extractHitObservables(hit({
      host: 'ws-[masked]',
      matched: [matchedField('principal.ip', 'not-an-ip'), matchedField('network.dns.domain', '10.0.0.4.x'), matchedField('target.file.sha256', 'xyz')],
    }))).toEqual([]);
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
    hits_sample: [
      hit({ timestamp: '2026-10-04T08:00:00.000Z', host: 'ws-042', user: 'alice', matched: [matchedField('target.process.command_line', 'powershell -enc AAAA')] }),
      hit({
        timestamp: '2026-10-04T18:00:00.000Z',
        host: 'ws-042',
        user: 'bob',
        matched: [{ field: 'target.process.command_line', value_hash: 'x', value_preview: null, value_complete: false }],
      }),
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
    expect(content.description).toContain('Matched fields: target.process.command_line (2)');
    expect(content.description).toContain('Hosts: ws-042 (2)');
    expect(content.description).toContain('host ws-042, user alice, target.process.command_line = powershell -enc AAAA');
    expect(content.description).toContain(HUNT_INCIDENT_RECOMMENDATION);
    expect(content.description).not.toContain('Hunt hypothesis: \n');
  });

  it('should fall back on the window and a medium severity without hits dates nor rule level', () => {
    const bare = { ...hunt, sigma_rule: null, description: null } as unknown as BasicStoreEntityHunt;
    const content = buildHuntIncidentContent(bare, { ...run, first_hit_at: null, last_hit_at: null, hits_sample: [] }, null, null);
    expect(content.severity).toEqual('medium');
    expect(content.first_seen).toEqual(run.time_window_start);
    expect(content.description).not.toContain('Hunt hypothesis');
    expect(content.description).toContain('reported no single hit');
  });

  it('should relate the incident to the hunt, its sources, targets and techniques, the platform and the hit observations', () => {
    expect(huntIncidentRelatedIds(hunt, run)).toEqual(['hunt-1', 'indicator-1', 'org-1', 'technique-1', 'platform-1', 'observed-data-1', 'hostname-1']);
  });
});
