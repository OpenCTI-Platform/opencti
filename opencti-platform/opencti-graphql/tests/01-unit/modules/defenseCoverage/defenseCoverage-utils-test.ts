import { describe, expect, it } from 'vitest';
import {
  buildCsv,
  buildLogsourceMappingKey,
  buildValidationTargets,
  capEvidences,
  cellForPlatform,
  collectCoverageIds,
  computeAggregateLevel,
  computeDetectionStatus,
  computeGapPriority,
  computePlatformLevel,
  computeRecommendedAction,
  computeThreatWeight,
  computeValidationStatus,
  countEffectiveTechniques,
  defaultValidationName,
  escapeCsvValue,
  evaluateCoverage,
  gapPlatformEvidence,
  isLogsourceMatching,
  latestValidation,
  mapLogsourceToDataComponents,
  rankRuleCandidates,
  validationEvidencePool,
  visibleParentId,
} from '../../../../src/modules/defenseCoverage/defenseCoverage-utils';
import { DEFENSE_AGGREGATE_PLATFORM, type DefenseCoverage, type DefenseValidationEvidence } from '../../../../src/modules/defenseCoverage/defenseCoverage-types';

const validation = (status: DefenseValidationEvidence['status'], date: string, id = 'scr-1'): DefenseValidationEvidence => ({
  id,
  rel: `rel-${id}-${date}`,
  status,
  last_result_at: date,
  scores: [],
});

const PLATFORM = 'platform-1';
const OTHER_PLATFORM = 'platform-2';

const buildCoverage = (): DefenseCoverage => ({
  computed_at: '2026-10-01T00:00:00.000Z',
  data_components: [{ id: 'dc-process', rel: 'detects-1' }],
  rules: [{ id: 'rule-1', rel: 'indicates-1' }, { id: 'rule-2', rel: 'indicates-2' }],
  mitigations: [{ id: 'coa-1', rel: 'mitigates-1' }],
  validations: [
    { id: 'scr-1', rel: 'covered-1', status: 'detected', last_result_at: '2026-09-01T00:00:00.000Z', scores: [{ name: 'DETECTION', score: 80 }] },
  ],
  platforms: [
    {
      platform_id: PLATFORM,
      telemetry: [{ id: 'dc-process', rel: 'provides-1', detects: 'detects-1' }],
      deployments: [{ id: 'rule-1', rel: 'deployed-1', status: 'active', indicates: 'indicates-1' }],
      validations: [
        { id: 'scr-1', rel: 'covered-1', status: 'detected', last_result_at: '2026-09-01T00:00:00.000Z', scores: [{ name: 'DETECTION', score: 80 }] },
      ],
      level: 4,
    },
    {
      platform_id: OTHER_PLATFORM,
      telemetry: [{ id: 'dc-process', rel: 'provides-2', detects: 'detects-1' }],
      deployments: [],
      validations: [],
      level: 2,
    },
  ],
  level: 4,
});

describe('Defense coverage validation status', () => {
  it('should be prevented when the prevention reaches the threshold', () => {
    expect(computeValidationStatus([{ name: 'PREVENTION', score: 60 }, { name: 'DETECTION', score: 100 }], 50)).toEqual('prevented');
  });
  it('should be detected when only the detection reaches the threshold', () => {
    expect(computeValidationStatus([{ name: 'prevention', score: 10 }, { name: 'detection', score: 50 }], 50)).toEqual('detected');
  });
  it('should be failed when detection or prevention was tested under the threshold', () => {
    expect(computeValidationStatus([{ name: 'DETECTION', score: 49 }], 50)).toEqual('failed');
  });
  it('should be none without any detection or prevention result', () => {
    expect(computeValidationStatus([{ name: 'VULNERABILITY', score: 100 }], 50)).toEqual('none');
    expect(computeValidationStatus([], 50)).toEqual('none');
  });
  it('should keep the latest result, the best one on a tie', () => {
    expect(latestValidation([validation('detected', '2026-01-01'), validation('failed', '2026-02-01')])?.status).toEqual('failed');
    expect(latestValidation([validation('detected', '2026-02-01'), validation('prevented', '2026-02-01')])?.status).toEqual('prevented');
    expect(latestValidation([validation('none', '2026-03-01')])).toBeUndefined();
  });
});

describe('Defense coverage detection status and levels', () => {
  it('should compute the detection status from deployments and available rules', () => {
    expect(computeDetectionStatus([{ id: 'r', rel: 'd', status: 'active', indicates: 'i' }], true)).toEqual('active');
    expect(computeDetectionStatus([{ id: 'r', rel: 'd', status: 'deployed', indicates: 'i' }], true)).toEqual('deployed');
    expect(computeDetectionStatus([{ id: 'r', rel: 'd', status: 'failed', indicates: 'i' }], true)).toEqual('available');
    expect(computeDetectionStatus([{ id: 'r', rel: 'd', status: 'removed', indicates: 'i' }], false)).toEqual('none');
  });
  it('should compute every platform level', () => {
    expect(computePlatformLevel(false, 'none', 'none')).toEqual(0);
    expect(computePlatformLevel(false, 'available', 'none')).toEqual(2);
    expect(computePlatformLevel(true, 'none', 'none')).toEqual(1);
    expect(computePlatformLevel(true, 'available', 'none')).toEqual(2);
    expect(computePlatformLevel(false, 'deployed', 'none')).toEqual(3);
    expect(computePlatformLevel(true, 'active', 'none')).toEqual(3);
    expect(computePlatformLevel(true, 'active', 'detected')).toEqual(4);
    expect(computePlatformLevel(false, 'none', 'prevented')).toEqual(4);
  });
  it('should cap the level at 2 when the latest validation failed', () => {
    expect(computePlatformLevel(true, 'active', 'failed')).toEqual(2);
    expect(computePlatformLevel(true, 'none', 'failed')).toEqual(1);
  });
  it('should compute the aggregated level', () => {
    expect(computeAggregateLevel([], false, false, 'none')).toEqual(0);
    expect(computeAggregateLevel([], true, false, 'none')).toEqual(1);
    expect(computeAggregateLevel([1], true, true, 'none')).toEqual(2);
    expect(computeAggregateLevel([3, 1], true, true, 'none')).toEqual(3);
    expect(computeAggregateLevel([0], false, false, 'detected')).toEqual(4);
    expect(computeAggregateLevel([3], true, true, 'failed')).toEqual(3);
  });
  it('should recommend the next action', () => {
    const base = { telemetry: true, detection: 'none' as const, validated: 'none' as const, hasDetectingDataComponent: true };
    expect(computeRecommendedAction({ ...base, level: 4, validated: 'detected' })).toEqual('none');
    expect(computeRecommendedAction({ ...base, level: 2, detection: 'active', validated: 'failed' })).toEqual('fix_detection');
    expect(computeRecommendedAction({ ...base, level: 3, detection: 'deployed' })).toEqual('activate_rule');
    expect(computeRecommendedAction({ ...base, level: 3, detection: 'active' })).toEqual('validate');
    expect(computeRecommendedAction({ ...base, level: 2, detection: 'available' })).toEqual('deploy_rule');
    // A platform that does not collect the telemetry of the technique cannot run its rule: the telemetry comes first
    expect(computeRecommendedAction({ ...base, level: 2, detection: 'available', telemetry: false })).toEqual('add_telemetry');
    expect(computeRecommendedAction({ ...base, level: 1 })).toEqual('import_rule');
    expect(computeRecommendedAction({ ...base, level: 0, telemetry: false })).toEqual('add_telemetry');
    expect(computeRecommendedAction({ ...base, level: 0, telemetry: false, hasDetectingDataComponent: false })).toEqual('import_rule');
  });
});

describe('Defense coverage evaluation for a reader', () => {
  it('should evaluate the full coverage when every evidence is visible', () => {
    const cell = evaluateCoverage('ap-1', buildCoverage(), () => true);
    expect(cell.level).toEqual(4);
    expect(cell.telemetry).toEqual(true);
    expect(cell.detection).toEqual('active');
    expect(cell.validated).toEqual('detected');
    expect(cell.mitigated).toEqual(true);
    expect(cell.rule_ids).toEqual(['rule-1', 'rule-2']);
    expect(cellForPlatform(cell, PLATFORM).level).toEqual(4);
    expect(cellForPlatform(cell, OTHER_PLATFORM).level).toEqual(2);
    expect(cellForPlatform(cell, OTHER_PLATFORM).recommended_action).toEqual('deploy_rule');
  });
  it('should drop the evidences the reader cannot access', () => {
    const hidden = new Set(['deployed-1', 'covered-1']);
    const cell = evaluateCoverage('ap-1', buildCoverage(), (id) => !!id && !hidden.has(id));
    const platform = cellForPlatform(cell, PLATFORM);
    expect(platform.detection).toEqual('available');
    expect(platform.validated).toEqual('none');
    expect(platform.level).toEqual(2);
    expect(cell.level).toEqual(2);
    expect(cell.coverage_result_ids).toEqual([]);
  });
  it('should drop an inferred telemetry when only its indicates relationship is hidden', () => {
    const base = buildCoverage();
    const inferred = { id: 'dc-process', rel: 'deployed-1', detects: 'detects-1', inferred_from: 'rule-1', indicates: 'indicates-1' };
    const coverage: DefenseCoverage = {
      ...base,
      platforms: [{ ...base.platforms[0], telemetry: [inferred], deployments: [], validations: [], level: 1 }],
      validations: [],
    };
    const visible = cellForPlatform(evaluateCoverage('ap-1', coverage, () => true), PLATFORM);
    expect(visible.telemetry).toEqual(true);
    const hidden = cellForPlatform(evaluateCoverage('ap-1', coverage, (id) => !!id && id !== 'indicates-1'), PLATFORM);
    expect(hidden.telemetry).toEqual(false);
    expect(hidden.inferred_data_component_ids).toEqual([]);
    // A stored inferred telemetry without its indicates relationship is never trusted
    const withoutIndicates = { id: 'dc-process', rel: 'deployed-1', detects: 'detects-1', inferred_from: 'rule-1' };
    const legacy: DefenseCoverage = { ...coverage, platforms: [{ ...coverage.platforms[0], telemetry: [withoutIndicates] }] };
    expect(cellForPlatform(evaluateCoverage('ap-1', legacy, () => true), PLATFORM).telemetry).toEqual(false);
    expect(collectCoverageIds(coverage)).toContain('indicates-1');
  });
  it('should hide a platform the reader cannot access', () => {
    const cell = evaluateCoverage('ap-1', buildCoverage(), (id) => !!id && id !== PLATFORM);
    expect(cell.platforms.map((p) => p.platform_id)).toEqual([OTHER_PLATFORM]);
    // The OpenAEV result is attributed to the hidden platform, it does not count as unattributed
    expect(cell.level).toEqual(2);
  });
  it('should restrict the evaluation to the selected platforms', () => {
    const cell = evaluateCoverage('ap-1', buildCoverage(), () => true, [OTHER_PLATFORM]);
    expect(cell.platforms).toHaveLength(1);
    expect(cell.level).toEqual(2);
  });
  it('should count results not attributed to any platform only without selection', () => {
    const coverage: DefenseCoverage = {
      ...buildCoverage(),
      platforms: [],
      validations: [{ id: 'scr-2', rel: 'covered-2', status: 'prevented', last_result_at: '2026-09-02T00:00:00.000Z', scores: [] }],
    };
    expect(evaluateCoverage('ap-1', coverage, () => true).level).toEqual(4);
    expect(evaluateCoverage('ap-1', coverage, () => true, [PLATFORM]).level).toEqual(2);
  });
  it('should never count an attributed result as unattributed when the platform lists were capped', () => {
    const coverage: DefenseCoverage = {
      ...buildCoverage(),
      platforms: [],
      validations: [{ id: 'scr-2', rel: 'covered-2', status: 'prevented', last_result_at: '2026-09-02T00:00:00.000Z', scores: [], attributed: true }],
    };
    expect(evaluateCoverage('ap-1', coverage, () => true).level).toEqual(2);
    expect(evaluateCoverage('ap-1', coverage, () => true).coverage_result_ids).toEqual([]);
  });
  it('should cap the technique at 2 when its latest validation failed', () => {
    const base = buildCoverage();
    const coverage: DefenseCoverage = {
      ...base,
      validations: [{ id: 'scr-3', rel: 'covered-3', status: 'failed', last_result_at: '2026-09-03T00:00:00.000Z', scores: [] }],
      platforms: [{ ...base.platforms[0], validations: [], level: 3 }],
    };
    const cell = evaluateCoverage('ap-1', coverage, () => true);
    expect(cell.validated).toEqual('failed');
    expect(cellForPlatform(cell, PLATFORM).level).toEqual(3);
    expect(cell.level).toEqual(2);
  });
  it('should keep a platform validation when another result failed later', () => {
    const coverage: DefenseCoverage = {
      ...buildCoverage(),
      validations: [{ id: 'scr-3', rel: 'covered-3', status: 'failed', last_result_at: '2026-09-03T00:00:00.000Z', scores: [] }],
    };
    expect(evaluateCoverage('ap-1', coverage, () => true).level).toEqual(4);
  });
  it('should default the cell of a platform without any evidence', () => {
    const cell = evaluateCoverage('ap-1', buildCoverage(), () => true);
    const missing = cellForPlatform(cell, 'platform-unknown');
    expect(missing.level).toEqual(2);
    expect(missing.detection).toEqual('available');
    expect(missing.recommended_action).toEqual('add_telemetry');
  });
  it('should evaluate a technique without stored coverage', () => {
    const cell = evaluateCoverage('ap-2', undefined, () => true);
    expect(cell.level).toEqual(0);
    expect(cell.recommended_action).toEqual('import_rule');
  });
  it('should collect every id needed to check the evidences', () => {
    const ids = collectCoverageIds(buildCoverage());
    ['dc-process', 'detects-1', 'rule-1', 'indicates-1', 'coa-1', 'scr-1', 'covered-1', PLATFORM, 'provides-1', 'deployed-1'].forEach((id) => {
      expect(ids).toContain(id);
    });
    expect(new Set(ids).size).toEqual(ids.length);
    expect(collectCoverageIds(undefined)).toEqual([]);
  });
});

describe('Defense validation evidence pool', () => {
  it('should keep a per-platform result missing from the capped technique-wide list', () => {
    const coverage = buildCoverage();
    const platformOnly = { id: 'scr-2', rel: 'covered-2', status: 'prevented' as const, last_result_at: '2026-09-10T00:00:00.000Z', scores: [] };
    coverage.platforms[1].validations.push(platformOnly);
    const pool = validationEvidencePool(coverage);
    expect(pool.map((v) => `${v.id}|${v.rel}`)).toEqual(['scr-1|covered-1', 'scr-2|covered-2']);
    expect(pool[1]).toBe(platformOnly);
  });
  it('should list a result once and prefer its technique-wide entry', () => {
    const coverage = buildCoverage();
    const pool = validationEvidencePool(coverage);
    expect(pool).toHaveLength(1);
    expect(pool[0]).toBe(coverage.validations[0]);
    expect(validationEvidencePool(undefined)).toEqual([]);
  });
});

describe('Defense validation targets', () => {
  const pairs = (targets: { attackPatternId: string; platformId: string }[]) => targets.map((t) => `${t.attackPatternId}|${t.platformId}`).sort();
  it('should track every technique on its aggregate gap and on every requested platform', () => {
    expect(pairs(buildValidationTargets(['ap-a', 'ap-b'], ['p1'], []))).toEqual(['ap-a|all', 'ap-a|p1', 'ap-b|all', 'ap-b|p1']);
  });
  it('should track the selected gaps as pairs, never crossing techniques and platforms', () => {
    const targets = buildValidationTargets(['ap-a', 'ap-b'], [], [
      { attackPatternId: 'ap-a', platformId: 'p1' },
      { attackPatternId: 'ap-b', platformId: 'p2' },
    ]);
    expect(pairs(targets)).toEqual(['ap-a|all', 'ap-a|p1', 'ap-b|all', 'ap-b|p2']);
  });
  it('should track a pair once', () => {
    const targets = buildValidationTargets(['ap-a'], ['p1'], [{ attackPatternId: 'ap-a', platformId: 'p1' }, { attackPatternId: 'ap-a', platformId: 'all' }]);
    expect(pairs(targets)).toEqual(['ap-a|all', 'ap-a|p1']);
  });
});

describe('Defense validation name', () => {
  it('should name a request without a name by its threat, else by the number of its techniques', () => {
    expect(defaultValidationName(1, undefined, '2026-10-06T19:53:15.000Z')).toBe('Defense validation - 1 technique - 2026-10-06');
    expect(defaultValidationName(3, null, '2026-10-06T19:53:15.000Z')).toBe('Defense validation - 3 techniques - 2026-10-06');
    expect(defaultValidationName(3, 'APT28', '2026-10-06T19:53:15.000Z')).toBe('Defense validation - APT28 - 2026-10-06');
  });
});

describe('Defense matrix parent techniques', () => {
  const sub = { parent_id: 'parent', parent_rel_id: 'subtechnique-of-1' };
  it('should show the parent to a reader of the parent and of the relationship', () => {
    expect(visibleParentId(sub, () => true)).toEqual('parent');
  });
  it('should hide the parent when the subtechnique-of relationship is restricted', () => {
    expect(visibleParentId(sub, (id) => id !== 'subtechnique-of-1')).toBeUndefined();
  });
  it('should hide the parent when the parent technique is restricted', () => {
    expect(visibleParentId(sub, (id) => id !== 'parent')).toBeUndefined();
  });
  it('should never expose a parent without its relationship', () => {
    expect(visibleParentId({ parent_id: 'parent' }, () => true)).toBeUndefined();
    expect(visibleParentId({}, () => true)).toBeUndefined();
  });
});

describe('Defense matrix totals', () => {
  it('should count a parent with the best level and usage of its sub-techniques', () => {
    const effective = countEffectiveTechniques([
      { attack_pattern_id: 'parent', level: 1, threats_count: 0 },
      { attack_pattern_id: 'sub', parent_attack_pattern_id: 'parent', level: 3, threats_count: 2 },
      { attack_pattern_id: 'other', level: 0, threats_count: 0 },
    ]);
    expect(Object.fromEntries(effective)).toEqual({ parent: { level: 3, used: true, threat_level: 3 }, other: { level: 0, used: false, threat_level: 0 } });
  });

  it('should never count the coverage of an unused sub-technique for a used sibling', () => {
    const effective = countEffectiveTechniques([
      { attack_pattern_id: 'parent', level: 0, threats_count: 0 },
      { attack_pattern_id: 'covered-unused', parent_attack_pattern_id: 'parent', level: 3, threats_count: 0 },
      { attack_pattern_id: 'uncovered-used', parent_attack_pattern_id: 'parent', level: 1, threats_count: 2 },
    ]);
    expect(effective.get('parent')).toEqual({ level: 3, used: true, threat_level: 1 });
  });

  it('should count the evidences of a parent for the sub-techniques the threats use', () => {
    const viaSub = countEffectiveTechniques([
      { attack_pattern_id: 'parent', level: 2, threats_count: 0 },
      { attack_pattern_id: 'uncovered-used', parent_attack_pattern_id: 'parent', level: 0, threats_count: 1 },
    ]);
    expect(viaSub.get('parent')).toEqual({ level: 2, used: true, threat_level: 2 });
    const direct = countEffectiveTechniques([
      { attack_pattern_id: 'parent', level: 1, threats_count: 3 },
      { attack_pattern_id: 'covered-unused', parent_attack_pattern_id: 'parent', level: 4, threats_count: 0 },
    ]);
    expect(direct.get('parent')).toEqual({ level: 4, used: true, threat_level: 1 });
  });

  it('should count on its own a sub-technique whose parent is not visible', () => {
    const effective = countEffectiveTechniques([{ attack_pattern_id: 'orphan', parent_attack_pattern_id: 'revoked-or-restricted', level: 2, threats_count: 1 }]);
    expect(Object.fromEntries(effective)).toEqual({ orphan: { level: 2, used: true, threat_level: 2 } });
  });
});

describe('Defense gap threat weight and priority', () => {
  it('should weight each threat once by its strongest usage', () => {
    expect(computeThreatWeight([
      { threat_id: 't1', relationship_id: 'r1', confidence: 50 },
      { threat_id: 't1', relationship_id: 'r2', confidence: 90 },
      { threat_id: 't2', relationship_id: 'r3', confidence: 0 },
    ])).toEqual(1);
    expect(computeThreatWeight([])).toEqual(0);
  });
  it('should rank gaps by severity and threat relevance', () => {
    expect(computeGapPriority(4, 10)).toEqual(0);
    expect(computeGapPriority(0, 0)).toEqual(10);
    expect(computeGapPriority(0, 10)).toBeGreaterThan(computeGapPriority(0, 1));
    expect(computeGapPriority(0, 1)).toBeGreaterThan(computeGapPriority(2, 1));
    expect(computeGapPriority(0, 100)).toBeLessThanOrEqual(100);
  });
});

describe('Defense log source mapping', () => {
  const entries = [
    { x_opencti_rule_logsource: { category: 'process_creation' }, data_components: ['Process Creation', 'Command Execution'] },
    { x_opencti_rule_logsource: { category: 'process_creation', product: 'windows' }, data_components: ['process creation'] },
    { x_opencti_rule_logsource: { product: 'windows', service: 'security' }, data_components: ['Logon Session Creation'] },
    { x_opencti_rule_logsource: { product: 'linux' }, data_components: ['Inactive'], active: false },
    { x_opencti_rule_logsource: {}, data_components: ['Never'] },
    { data_components: ['Never either'] },
  ];
  it('should match the fields set on the entry only', () => {
    expect(isLogsourceMatching(entries[0], { category: 'Process_Creation', product: 'linux' })).toEqual(true);
    expect(isLogsourceMatching(entries[1], { category: 'process_creation', product: 'linux' })).toEqual(false);
    expect(isLogsourceMatching(entries[4], { category: 'process_creation' })).toEqual(false);
    expect(isLogsourceMatching(entries[5], { category: 'process_creation' })).toEqual(false);
  });
  it('should map a log source to deduplicated data components', () => {
    expect(mapLogsourceToDataComponents({ category: 'process_creation', product: 'windows' }, entries)).toEqual(['Process Creation', 'Command Execution']);
    expect(mapLogsourceToDataComponents({ product: 'windows', service: 'security' }, entries)).toEqual(['Logon Session Creation']);
    expect(mapLogsourceToDataComponents({ product: 'linux' }, entries)).toEqual([]);
    expect(mapLogsourceToDataComponents(undefined, entries)).toEqual([]);
  });
  it('should build a stable mapping key', () => {
    expect(buildLogsourceMappingKey(' Process_Creation ', 'Windows', null)).toEqual('process_creation|windows|');
  });
});

describe('Defense rule candidates and export', () => {
  it('should rank compatible, mature and severe rules first', () => {
    const ranked = rankRuleCandidates([
      { id: 'experimental', x_opencti_rule_status: 'experimental', x_opencti_rule_level: 'critical', compatible: true },
      { id: 'incompatible', x_opencti_rule_status: 'stable', x_opencti_rule_level: 'critical', compatible: false },
      { id: 'stable-high', x_opencti_rule_status: 'stable', x_opencti_rule_level: 'high', compatible: true },
      { id: 'stable-critical', x_opencti_rule_status: 'stable', x_opencti_rule_level: 'critical', compatible: true },
    ]);
    expect(ranked.map((r) => r.id)).toEqual(['stable-critical', 'stable-high', 'experimental', 'incompatible']);
  });
  it('should escape CSV values and neutralize formulas', () => {
    expect(escapeCsvValue('=HYPERLINK("x")')).toEqual('"\'=HYPERLINK(""x"")"');
    expect(escapeCsvValue('-1+1')).toEqual('\'-1+1');
    expect(escapeCsvValue('a,b')).toEqual('"a,b"');
    expect(escapeCsvValue(['r1', 'r2'])).toEqual('"r1; r2"');
    expect(escapeCsvValue(null)).toEqual('');
    expect(escapeCsvValue(3)).toEqual('3');
  });
  it('should build a CSV document', () => {
    expect(buildCsv(['id', 'name'], [['T1059', 'Command and Scripting Interpreter']])).toEqual('id,name\r\nT1059,Command and Scripting Interpreter\r\n');
  });
});

describe('Defense gap platform evidence', () => {
  it('should count what any platform provides and deploys on the row of all platforms', () => {
    const cell = evaluateCoverage('ap-1', buildCoverage(), () => true);
    expect(cell.rule_ids).toEqual(['rule-1', 'rule-2']);
    // rule-2 is deployed nowhere: it stays a candidate of the row of all platforms
    expect(gapPlatformEvidence(cell, DEFENSE_AGGREGATE_PLATFORM)).toEqual({ data_component_ids: ['dc-process'], rule_ids: ['rule-1'] });
    expect(gapPlatformEvidence(cell, OTHER_PLATFORM)).toEqual({ data_component_ids: ['dc-process'], rule_ids: [] });
  });
  it('should leave the telemetry no platform provides missing on the row of all platforms', () => {
    const base = buildCoverage();
    const coverage: DefenseCoverage = { ...base, platforms: base.platforms.map((p) => ({ ...p, telemetry: [] })) };
    const cell = evaluateCoverage('ap-1', coverage, () => true);
    expect(cell.data_component_ids).toEqual(['dc-process']);
    expect(gapPlatformEvidence(cell, DEFENSE_AGGREGATE_PLATFORM).data_component_ids).toEqual([]);
  });
});

describe('Defense evidence cap', () => {
  const restricted = Array.from({ length: 5 }, (_, index) => ({ id: `restricted-${index}`, key: 'secret' }));
  const visible = { id: 'visible', key: 'public' };
  it('should keep the first evidences without an access key', () => {
    expect(capEvidences([...restricted, visible], 3).map((e) => e.id)).toEqual(['restricted-0', 'restricted-1', 'restricted-2']);
  });
  it('should keep an evidence of every access signature before filling the cap', () => {
    const capped = capEvidences([...restricted, visible], 3, (e) => e.key);
    expect(capped.map((e) => e.id)).toEqual(['restricted-0', 'visible', 'restricted-1']);
  });
  it('should leave a list under the cap untouched', () => {
    const evidences = [...restricted, visible];
    expect(capEvidences(evidences, 10, (e) => e.key)).toBe(evidences);
  });
  it('should keep every access signature even when they outnumber the cap', () => {
    const partitions = Array.from({ length: 5 }, (_, index) => [
      { id: `p${index}-a`, key: `signature-${index}` },
      { id: `p${index}-b`, key: `signature-${index}` },
    ]).flat();
    const capped = capEvidences(partitions, 3, (e) => e.key);
    expect(capped.map((e) => e.id)).toEqual(['p0-a', 'p1-a', 'p2-a', 'p3-a', 'p4-a']);
  });
  it('should bound the access signatures kept by the partition limit', () => {
    const partitions = Array.from({ length: 10 }, (_, index) => [
      { id: `p${index}-a`, key: `signature-${index}` },
      { id: `p${index}-b`, key: `signature-${index}` },
    ]).flat();
    // The partitions of the first evidences in preference order are kept, never more than the limit
    expect(capEvidences(partitions, 3, (e) => e.key, undefined, 4).map((e) => e.id)).toEqual(['p0-a', 'p1-a', 'p2-a', 'p3-a']);
    // The default limit is four times the evidence bound
    expect(capEvidences(partitions, 2, (e) => e.key)).toHaveLength(8);
    // The limit never drops below the evidence bound itself
    expect(capEvidences(partitions, 5, (e) => e.key, undefined, 1).map((e) => e.id)).toEqual(['p0-a', 'p1-a', 'p2-a', 'p3-a', 'p4-a']);
  });
  it('should keep every level class of an access signature', () => {
    const deployments = [
      { id: 'rule-1', status: 'deployed', key: 'tlp-amber' },
      { id: 'rule-2', status: 'deployed', key: 'tlp-amber' },
      { id: 'rule-3', status: 'deployed', key: 'tlp-amber' },
      { id: 'rule-4', status: 'active', key: 'tlp-amber' },
    ];
    expect(capEvidences(deployments, 2, (e) => e.key).map((e) => e.id)).toEqual(['rule-1', 'rule-2']);
    expect(capEvidences(deployments, 2, (e) => e.key, (e) => e.status).map((e) => e.id)).toEqual(['rule-1', 'rule-4']);
  });
});
