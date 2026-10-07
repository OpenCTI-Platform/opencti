import { describe, expect, it } from 'vitest';
import '../../../../src/modules/defenseCoverage/defenseGap/defenseGap';
import {
  accessSignature,
  activeMitigations,
  buildTechniqueCoverage,
  currentCoverageResults,
  type ComputationGraph,
  defenseGapId,
  isProducedGap,
  withoutRevokedDataComponents,
  withoutRevokedRelations,
} from '../../../../src/modules/defenseCoverage/defenseCoverage-compute';
import { collectDefenseImpact } from '../../../../src/modules/defenseCoverage/defenseCoverage-impact';
import { builtInRestoreAction, DEFENSE_LOGSOURCE_MAPPING_DEFAULTS } from '../../../../src/modules/defenseCoverage/defenseLogsourceMapping/defenseLogsourceMapping-domain';
import { buildLogsourceMappingKey, capEvidences } from '../../../../src/modules/defenseCoverage/defenseCoverage-utils';
import { STIX_EXT_OCTI } from '../../../../src/types/stix-2-1-extensions';
import type { BasicStoreEntity, BasicStoreRelation } from '../../../../src/types/store';
import type { BasicStoreEntityIndicator } from '../../../../src/modules/indicator/indicator-types';

const relation = (id: string, fromId: string, toId: string, extra: Record<string, unknown> = {}) => {
  return { id, internal_id: id, fromId, toId, ...extra } as unknown as BasicStoreRelation;
};

const AP = 'attack-pattern-1';
const SIEM = 'platform-siem';
const EDR = 'platform-edr';

const buildGraph = (): ComputationGraph => {
  const rule = {
    internal_id: 'rule-1',
    pattern_type: 'sigma',
    x_opencti_rule_logsource: { category: 'process_creation', product: 'windows' },
  } as unknown as BasicStoreEntityIndicator;
  // A loaded result holds its single result-of ref as an id, as the engine data converter rebuilds it
  const result = { internal_id: 'scr-1', coverage_last_result: '2026-09-01T00:00:00.000Z', 'result-of': 'coverage-1' } as unknown as BasicStoreEntity;
  return {
    platforms: [
      { id: SIEM, name: 'SIEM', entity_type: 'SecurityPlatform', stix_ids: ['identity--siem'] },
      { id: EDR, name: 'EDR', entity_type: 'SecurityPlatform', stix_ids: ['identity--edr'] },
    ],
    platformIdByStixId: new Map([['identity--siem', SIEM], ['identity--edr', EDR]]),
    detectsByTechnique: new Map([[AP, [relation('detects-1', 'dc-process', AP), relation('detects-2', 'dc-command', AP)]]]),
    providesByDataComponent: new Map([['dc-command', [relation('provides-1', SIEM, 'dc-command')]]]),
    indicatesByTechnique: new Map([[AP, [relation('indicates-1', 'rule-1', AP), relation('indicates-ioc', 'ioc-1', AP)]]]),
    rulesById: new Map([['rule-1', rule]]),
    deploymentsByRule: new Map([['rule-1', [relation('deployed-1', 'rule-1', EDR, { deployment_status: 'active' })]]]),
    mitigatesByTechnique: new Map([[AP, [relation('mitigates-1', 'coa-1', AP)]]]),
    hasCoveredByTechnique: new Map([[AP, [relation('covered-1', 'scr-1', AP, {
      coverage_information: [{ coverage_name: 'DETECTION', coverage_score: 70 }],
      coverage_platforms_information: [
        { platform_ref: 'identity--edr', coverage_name: 'DETECTION', coverage_score: 90 },
        { platform_ref: 'identity--siem', coverage_name: 'DETECTION', coverage_score: 10 },
        { platform_ref: 'identity--unknown', coverage_name: 'DETECTION', coverage_score: 100 },
      ],
    })]]]),
    resultsById: new Map([['scr-1', result]]),
    dataComponentIdsByName: new Map([['process creation', ['dc-process']], ['command execution', ['dc-command']]]),
    mappings: [{ x_opencti_rule_logsource: { category: 'process_creation' }, data_components: ['Process Creation'], active: true }],
  };
};

describe('Defense coverage vector building', () => {
  const coverage = buildTechniqueCoverage(AP, buildGraph(), '2026-10-01T00:00:00.000Z');
  const vectorOf = (platformId: string) => coverage.platforms.find((p) => p.platform_id === platformId);

  it('should keep the technique wide evidences', () => {
    expect(coverage.data_components.map((d) => d.id)).toEqual(['dc-process', 'dc-command']);
    expect(coverage.rules).toEqual([{ id: 'rule-1', rel: 'indicates-1' }]);
    expect(coverage.mitigations).toEqual([{ id: 'coa-1', rel: 'mitigates-1' }]);
    expect(coverage.validations[0]).toMatchObject({ id: 'scr-1', coverage_id: 'coverage-1', status: 'detected', last_result_at: '2026-09-01T00:00:00.000Z' });
  });
  it('should attribute the telemetry declared through provides', () => {
    expect(vectorOf(SIEM)?.telemetry).toEqual([{ id: 'dc-command', rel: 'provides-1', detects: 'detects-2' }]);
  });
  it('should infer the telemetry of a deployed rule from its log source', () => {
    const edr = vectorOf(EDR);
    expect(edr?.deployments).toEqual([{ id: 'rule-1', rel: 'deployed-1', status: 'active', indicates: 'indicates-1' }]);
    expect(edr?.telemetry).toEqual([{ id: 'dc-process', rel: 'deployed-1', detects: 'detects-1', inferred_from: 'rule-1', indicates: 'indicates-1' }]);
  });
  it.each(['pending', 'failed', 'removed', 'expired'])('should not infer telemetry from a %s deployment', (status) => {
    const graph = buildGraph();
    graph.deploymentsByRule = new Map([['rule-1', [relation('deployed-1', 'rule-1', EDR, { deployment_status: status })]]]);
    const edr = buildTechniqueCoverage(AP, graph, '2026-10-01T00:00:00.000Z').platforms.find((p) => p.platform_id === EDR);
    expect(edr?.deployments).toEqual([{ id: 'rule-1', rel: 'deployed-1', status, indicates: 'indicates-1' }]);
    expect(edr?.telemetry).toEqual([]);
  });
  it('should attribute the OpenAEV results per security platform', () => {
    expect(vectorOf(EDR)?.validations[0]).toMatchObject({ status: 'detected', scores: [{ name: 'DETECTION', score: 90 }] });
    expect(vectorOf(SIEM)?.validations[0]).toMatchObject({ status: 'failed', scores: [{ name: 'DETECTION', score: 10 }] });
    expect(coverage.platforms.map((p) => p.platform_id).sort()).toEqual([EDR, SIEM].sort());
  });
  it('should store the system levels', () => {
    expect(vectorOf(EDR)?.level).toEqual(4);
    // telemetry and an available rule, but the latest validation failed
    expect(vectorOf(SIEM)?.level).toEqual(2);
    expect(coverage.level).toEqual(4);
  });
});

describe('Defense coverage of the current OpenAEV results', () => {
  const AT = '2026-10-01T00:00:00.000Z';
  const result = (id: string, extra: Record<string, unknown> = {}) => ({ internal_id: id, ...extra } as unknown as BasicStoreEntity);

  it('should keep the results valid at the computation date', () => {
    const results = [
      result('undated'),
      result('in-window', { coverage_valid_from: '2026-09-01T00:00:00.000Z', coverage_valid_to: '2026-11-01T00:00:00.000Z' }),
      result('expired', { coverage_valid_to: '2026-09-30T00:00:00.000Z' }),
      result('future', { coverage_valid_from: '2026-10-02T00:00:00.000Z' }),
      result('revoked', { revoked: true }),
    ];
    expect(currentCoverageResults(results, AT).map((r) => r.internal_id)).toEqual(['undated', 'in-window']);
  });
});

describe('Defense coverage of platform-scoped OpenAEV results', () => {
  const coverageWith = (platformsInformation: { platform_ref: string; coverage_name: string; coverage_score: number }[]) => {
    const graph = buildGraph();
    graph.hasCoveredByTechnique = new Map([[AP, [relation('covered-1', 'scr-1', AP, {
      coverage_information: [{ coverage_name: 'DETECTION', coverage_score: 100 }],
      coverage_platforms_information: platformsInformation,
    })]]]);
    return buildTechniqueCoverage(AP, graph, '2026-10-01T00:00:00.000Z');
  };

  it('should never count a result scoped to unresolved platforms technique-wide', () => {
    const coverage = coverageWith([{ platform_ref: 'identity--deleted', coverage_name: 'DETECTION', coverage_score: 100 }]);
    expect(coverage.validations[0]).toMatchObject({ rel: 'covered-1', attributed: true });
    expect(coverage.platforms.flatMap((p) => p.validations)).toEqual([]);
    expect(coverage.level).toBeLessThan(4);
  });
  it('should count a result without platform attribution technique-wide', () => {
    const coverage = coverageWith([]);
    expect(coverage.validations[0]).toMatchObject({ rel: 'covered-1', attributed: false });
    expect(coverage.level).toEqual(4);
  });
});

describe('Defense evidence access signature', () => {
  type Member = { id: string; access_right: string; groups_restriction_ids?: string[] };
  const element = (members?: Member[], authorities?: string[], id = 'e') => ({
    internal_id: id,
    'object-marking': ['m2', 'm1'],
    restricted_members: members,
    authorized_authorities: authorities,
  } as unknown as BasicStoreEntity);

  it('should separate evidences by their stored member restrictions', () => {
    const open = accessSignature(element());
    const restricted = accessSignature(element([{ id: 'group-1', access_right: 'view' }]));
    expect(restricted).not.toEqual(open);
    expect(open).toEqual('m1,m2;;;');
    expect(restricted).toEqual('m1,m2;;group-1:view:;');
  });
  it('should separate evidences by the groups restriction of a member', () => {
    const member = { id: 'organization-1', access_right: 'view' };
    const restricted = accessSignature(element([{ ...member, groups_restriction_ids: ['group-2', 'group-1'] }]));
    expect(restricted).not.toEqual(accessSignature(element([member])));
    expect(restricted).not.toEqual(accessSignature(element([{ ...member, groups_restriction_ids: ['group-1'] }])));
    expect(restricted).toEqual('m1,m2;;organization-1:view:group-1+group-2;');
  });
  it('should separate evidences by their authorized authorities', () => {
    const withAuthority = accessSignature(element(undefined, ['KNOWLEDGE_KNUPDATE', 'user-1']));
    expect(withAuthority).not.toEqual(accessSignature(element()));
    expect(withAuthority).toEqual('m1,m2;;;KNOWLEDGE_KNUPDATE,user-1');
  });
  it('should keep one evidence of every access partition when capping', () => {
    const member = { id: 'organization-1', access_right: 'view' };
    const evidences = [
      element([member], undefined, 'member'),
      element([member], undefined, 'member-again'),
      element([{ ...member, groups_restriction_ids: ['group-1'] }], undefined, 'grouped-member'),
      element([member], ['user-1'], 'member-with-authority'),
    ];
    const capped = capEvidences(evidences, 2, (evidence) => accessSignature(evidence));
    expect(capped.map((evidence) => evidence.internal_id)).toEqual(['member', 'grouped-member', 'member-with-authority']);
  });
});

describe('Defense telemetry of revoked data components', () => {
  it('should drop a revoked data component with its detects and provides relationships', () => {
    const dataComponents = [
      { internal_id: 'dc-active', name: 'Process Creation' },
      { internal_id: 'dc-revoked', name: 'Command Execution', revoked: true },
    ] as unknown as BasicStoreEntity[];
    const filtered = withoutRevokedDataComponents(
      dataComponents,
      [relation('detects-1', 'dc-active', AP), relation('detects-2', 'dc-revoked', AP)],
      [relation('provides-1', SIEM, 'dc-active'), relation('provides-2', SIEM, 'dc-revoked')],
    );
    expect(filtered.dataComponents.map((dc) => dc.internal_id)).toEqual(['dc-active']);
    expect(filtered.detects.map((r) => r.id)).toEqual(['detects-1']);
    expect(filtered.provides.map((r) => r.id)).toEqual(['provides-1']);
  });
});

describe('Defense evidence of revoked relationships', () => {
  it('should keep only the relationships that are not revoked', () => {
    const relations = [
      relation('detects-active', 'dc-1', AP, { revoked: false }),
      relation('detects-revoked', 'dc-1', AP, { revoked: true }),
      relation('indicates-without-attribute', 'rule-1', AP),
    ];
    expect(withoutRevokedRelations(relations).map((r) => r.id)).toEqual(['detects-active', 'indicates-without-attribute']);
  });
});

describe('Defense mitigations of revoked courses of action', () => {
  it('should keep only the mitigations of the courses of action that are loaded and not revoked', () => {
    const coursesOfAction = [
      { internal_id: 'coa-active' },
      { internal_id: 'coa-revoked', revoked: true },
    ] as unknown as BasicStoreEntity[];
    const mitigates = [relation('m-1', 'coa-active', AP), relation('m-2', 'coa-revoked', AP), relation('m-3', 'coa-unknown', AP)];
    expect(activeMitigations(mitigates, coursesOfAction).map((r) => r.id)).toEqual(['m-1']);
  });
});

describe('Defense gaps produced by a run', () => {
  const techniques = new Set([AP]);
  const platforms = new Set([SIEM]);
  const gap = (attackPatternId: string, platformId: string) => ({
    internal_id: defenseGapId(attackPatternId, platformId).internalId,
    attack_pattern_id: attackPatternId,
    platform_id: platformId,
  });

  it('should recognize the gap of a technique and platform of the run', () => {
    expect(isProducedGap(gap(AP, SIEM), techniques, platforms)).toBe(true);
  });
  it('should not recognize the gap of a technique or a platform out of the run', () => {
    expect(isProducedGap(gap('attack-pattern-revoked', SIEM), techniques, platforms)).toBe(false);
    expect(isProducedGap(gap(AP, EDR), techniques, platforms)).toBe(false);
    expect(isProducedGap({ ...gap(AP, SIEM), internal_id: 'other-id' }, techniques, platforms)).toBe(false);
    expect(isProducedGap({ internal_id: 'no-fields' }, techniques, platforms)).toBe(false);
  });
});

const event = (type: string, data: Record<string, unknown>) => ({ id: '1-0', event: type, data: { type, data } } as never);

describe('Defense coverage stream impact', () => {
  it('should collect techniques, data components and rules impacted by relationships', () => {
    const impact = collectDefenseImpact([
      event('create', { type: 'relationship', relationship_type: 'detects', extensions: { [STIX_EXT_OCTI]: { id: 'r1', type: 'detects', target_ref: AP, target_type: 'Attack-Pattern' } } }),
      event('delete', { type: 'relationship', relationship_type: 'provides', extensions: { [STIX_EXT_OCTI]: { id: 'r2', type: 'provides', source_ref: SIEM, target_ref: 'dc-1' } } }),
      event('create', { type: 'relationship', relationship_type: 'uses', extensions: { [STIX_EXT_OCTI]: { id: 'r4', type: 'uses', target_ref: 'ap-other', target_type: 'Attack-Pattern' } } }),
      event('update', { type: 'indicator', extensions: { [STIX_EXT_OCTI]: { id: 'rule-2', type: 'Indicator' } } }),
    ]);
    expect(impact.full).toEqual(false);
    expect(Array.from(impact.techniqueIds)).toEqual([AP]);
    expect(Array.from(impact.dataComponentIds)).toEqual(['dc-1']);
    expect(Array.from(impact.ruleIds)).toEqual(['rule-2']);
  });
  it('should ask for a full computation on platform creation and entity deletion', () => {
    expect(collectDefenseImpact([event('create', { type: 'identity', extensions: { [STIX_EXT_OCTI]: { id: 'p', type: 'SecurityPlatform' } } })]).full).toEqual(true);
    expect(collectDefenseImpact([event('delete', { type: 'x-mitre-data-component', extensions: { [STIX_EXT_OCTI]: { id: 'dc', type: 'Data-Component' } } })]).full).toEqual(true);
    expect(collectDefenseImpact([event('merge', { type: 'indicator', extensions: { [STIX_EXT_OCTI]: { id: 'i', type: 'Indicator' } } })]).full).toEqual(true);
    expect(collectDefenseImpact([event('delete', { type: 'report', extensions: { [STIX_EXT_OCTI]: { id: 'r', type: 'Report' } } })]).full).toEqual(false);
  });
  it('should invalidate the reader access when an evidence is updated', () => {
    const dataComponent = collectDefenseImpact([event('update', { type: 'x-mitre-data-component', extensions: { [STIX_EXT_OCTI]: { id: 'dc', type: 'Data-Component' } } })]);
    expect(dataComponent.accessChanged).toEqual(true);
    expect(Array.from(dataComponent.dataComponentIds)).toEqual(['dc']);
    // A revoked course of action withdraws the mitigation of the techniques it mitigates
    const courseOfAction = collectDefenseImpact([event('update', { type: 'course-of-action', extensions: { [STIX_EXT_OCTI]: { id: 'coa', type: 'Course-Of-Action' } } })]);
    expect(courseOfAction.accessChanged).toEqual(true);
    expect(Array.from(courseOfAction.mitigationIds)).toEqual(['coa']);
    const platform = collectDefenseImpact([event('update', { type: 'identity', extensions: { [STIX_EXT_OCTI]: { id: 'p', type: 'SecurityPlatform' } } })]);
    expect(platform.accessChanged).toEqual(true);
    expect(platform.full).toEqual(false);
    expect(collectDefenseImpact([event('update', { type: 'report', extensions: { [STIX_EXT_OCTI]: { id: 'r', type: 'Report' } } })]).accessChanged).toEqual(false);
  });
  it('should ask for a full computation when a system starts or stops providing telemetry', () => {
    const systemProvides = (type: string) => event(type, {
      type: 'relationship',
      relationship_type: 'provides',
      extensions: { [STIX_EXT_OCTI]: { id: 'p1', type: 'provides', source_ref: 'system-1', source_type: 'System', target_ref: 'dc-1' } },
    });
    expect(collectDefenseImpact([systemProvides('create')]).full).toEqual(true);
    expect(collectDefenseImpact([systemProvides('delete')]).full).toEqual(true);
    // Revoking the last provides of a system removes its column of gaps
    expect(collectDefenseImpact([systemProvides('update')]).full).toEqual(true);
    // A security platform is a defense platform with or without telemetry
    const platformProvides = collectDefenseImpact([event('create', {
      type: 'relationship',
      relationship_type: 'provides',
      extensions: { [STIX_EXT_OCTI]: { id: 'p2', type: 'provides', source_ref: SIEM, source_type: 'SecurityPlatform', target_ref: 'dc-2' } },
    })]);
    expect(platformProvides.full).toEqual(false);
    expect(Array.from(platformProvides.dataComponentIds)).toEqual(['dc-2']);
  });
  it.each([['SecurityPlatform', 'identity'], ['System', 'identity']])('should ask for a full computation when a %s is revoked or restored', (type, stixType) => {
    const updated = (path: string) => ({
      id: '1-0',
      event: 'update',
      data: { type: 'update', data: { type: stixType, extensions: { [STIX_EXT_OCTI]: { id: 'p', type } } }, context: { patch: [{ op: 'replace', path, value: true }] } },
    } as never);
    const revoked = collectDefenseImpact([updated('/revoked')]);
    expect(revoked.full).toEqual(true);
    expect(revoked.accessChanged).toEqual(true);
    expect(collectDefenseImpact([updated('/name')]).full).toEqual(false);
  });
  it.each(['create', 'update', 'merge', 'delete'])('should reload the tactics on a %s of a kill chain phase', (type) => {
    const impact = collectDefenseImpact([event(type, { type: 'kill-chain-phase', extensions: { [STIX_EXT_OCTI]: { id: 'kcp-1', type: 'Kill-Chain-Phase' } } })]);
    expect(impact.phasesChanged).toEqual(true);
    expect(impact.full).toEqual(false);
    expect(Array.from(impact.techniqueIds)).toEqual([]);
  });
  it('should recompute a technique whose kill chain phases change', () => {
    // Adding or removing a kill chain phase of a technique is streamed as an update of the attack pattern
    const impact = collectDefenseImpact([event('update', { type: 'attack-pattern', extensions: { [STIX_EXT_OCTI]: { id: AP, type: 'Attack-Pattern' } } })]);
    expect(Array.from(impact.techniqueIds)).toEqual([AP]);
    expect(impact.full).toEqual(false);
  });
  it('should recompute the techniques covered by an updated security coverage result', () => {
    const result = collectDefenseImpact([event('update', { type: 'x-security-coverage-result', extensions: { [STIX_EXT_OCTI]: { id: 'res-1', type: 'Security-Coverage-Result' } } })]);
    expect(Array.from(result.resultIds)).toEqual(['res-1']);
    expect(result.accessChanged).toEqual(true);
    expect(result.full).toEqual(false);
    const coverage = collectDefenseImpact([event('update', { type: 'security-coverage', extensions: { [STIX_EXT_OCTI]: { id: 'sc-1', type: 'Security-Coverage' } } })]);
    expect(Array.from(coverage.resultIds)).toEqual([]);
  });
  it('should invalidate the threat overlays when the usages or the access to a threat change', () => {
    const threat = { type: 'intrusion-set', extensions: { [STIX_EXT_OCTI]: { id: 'is-1', type: 'Intrusion-Set' } } };
    const updateWith = (path: string) => ({ id: '1-0', event: 'update', data: { type: 'update', data: threat, context: { patch: [{ op: 'add', path, value: 'x' }] } } } as never);
    const uses = collectDefenseImpact([
      event('delete', { type: 'relationship', relationship_type: 'uses', extensions: { [STIX_EXT_OCTI]: { id: 'u1', type: 'uses', source_ref: 'is-1', target_ref: AP, target_type: 'Attack-Pattern' } } }),
    ]);
    expect(uses.overlayChanged).toEqual(true);
    expect(Array.from(uses.techniqueIds)).toEqual([]);
    expect(collectDefenseImpact([event('create', { type: 'relationship', relationship_type: 'uses', extensions: { [STIX_EXT_OCTI]: { id: 'u2', type: 'uses', target_ref: 'malware-1', target_type: 'Malware' } } })]).overlayChanged).toEqual(false);
    expect(collectDefenseImpact([event('delete', threat)]).overlayChanged).toEqual(true);
    expect(collectDefenseImpact([event('merge', threat)]).overlayChanged).toEqual(true);
    expect(collectDefenseImpact([updateWith('/object_marking_refs/0')]).overlayChanged).toEqual(true);
    expect(collectDefenseImpact([updateWith('/extensions/extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba/granted_refs/0')]).overlayChanged).toEqual(true);
    // A routine update of a threat (description, aliases) keeps the overlays
    expect(collectDefenseImpact([updateWith('/description')]).overlayChanged).toEqual(false);
  });
  it('should flag every change of a threat or of its relationships for the filtered threat overlays', () => {
    const threat = { type: 'intrusion-set', extensions: { [STIX_EXT_OCTI]: { id: 'is-1', type: 'Intrusion-Set' } } };
    const routineUpdate = { id: '1-0', event: 'update', data: { type: 'update', data: threat, context: { patch: [{ op: 'add', path: '/labels/0', value: 'x' }] } } } as never;
    const routine = collectDefenseImpact([routineUpdate]);
    expect(routine.threatsChanged).toEqual(true);
    expect(routine.overlayChanged).toEqual(false);
    expect(collectDefenseImpact([event('create', threat)]).threatsChanged).toEqual(true);
    const targets = collectDefenseImpact([event('create', {
      type: 'relationship',
      relationship_type: 'targets',
      extensions: { [STIX_EXT_OCTI]: { id: 't1', type: 'targets', source_ref: 'is-1', source_type: 'Intrusion-Set', target_ref: 'sector-1', target_type: 'Sector' } },
    })]);
    expect(targets.threatsChanged).toEqual(true);
    expect(targets.overlayChanged).toEqual(false);
    const unrelated = collectDefenseImpact([event('create', {
      type: 'relationship',
      relationship_type: 'related-to',
      extensions: { [STIX_EXT_OCTI]: { id: 'r1', type: 'related-to', source_ref: 'report-1', source_type: 'Report', target_ref: 'sector-1', target_type: 'Sector' } },
    })]);
    expect(unrelated.threatsChanged).toEqual(false);
  });
});

describe('Defense log source mapping defaults', () => {
  it('should ship valid and unique built-in entries', () => {
    const keys = DEFENSE_LOGSOURCE_MAPPING_DEFAULTS.map((d) => buildLogsourceMappingKey(d.logsource_category, d.logsource_product, d.logsource_service));
    expect(new Set(keys).size).toEqual(keys.length);
    DEFENSE_LOGSOURCE_MAPPING_DEFAULTS.forEach((entry) => {
      expect(entry.logsource_category || entry.logsource_product || entry.logsource_service).toBeTruthy();
      expect(entry.data_components.length).toBeGreaterThan(0);
    });
  });
  it('should restore built-in entries and keep a custom mapping holding a built-in log source', () => {
    const shipped = { data_components: ['Process Creation'], description: 'Process creation' };
    expect(builtInRestoreAction(undefined, shipped)).toEqual('create');
    expect(builtInRestoreAction({ built_in: true, data_components: ['Process Creation'], active: true, description: 'Process creation' }, shipped)).toEqual('unchanged');
    expect(builtInRestoreAction({ built_in: true, data_components: ['Command Execution'], active: true, description: 'Process creation' }, shipped)).toEqual('restore');
    expect(builtInRestoreAction({ built_in: true, data_components: ['Process Creation'], active: false, description: 'Process creation' }, shipped)).toEqual('restore');
    // A custom mapping of the same log source is the organization's choice: never overwritten nor reclassified
    expect(builtInRestoreAction({ built_in: false, data_components: ['Command Execution'], active: false, description: 'Ours' }, shipped)).toEqual('keep_custom');
  });
});
