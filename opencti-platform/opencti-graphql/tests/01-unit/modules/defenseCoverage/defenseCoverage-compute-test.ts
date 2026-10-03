import { describe, expect, it } from 'vitest';
import { buildTechniqueCoverage, type ComputationGraph } from '../../../../src/modules/defenseCoverage/defenseCoverage-compute';
import { collectDefenseImpact } from '../../../../src/modules/defenseCoverage/defenseCoverage-impact';
import { DEFENSE_LOGSOURCE_MAPPING_DEFAULTS } from '../../../../src/modules/defenseCoverage/defenseLogsourceMapping/defenseLogsourceMapping-domain';
import { buildLogsourceMappingKey } from '../../../../src/modules/defenseCoverage/defenseCoverage-utils';
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
  const result = { internal_id: 'scr-1', coverage_last_result: '2026-09-01T00:00:00.000Z', 'result-of': ['coverage-1'] } as unknown as BasicStoreEntity;
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
    mappings: [{ logsource_category: 'process_creation', data_components: ['Process Creation'], active: true }],
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
    expect(edr?.telemetry).toEqual([{ id: 'dc-process', rel: 'deployed-1', detects: 'detects-1', inferred_from: 'rule-1' }]);
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

const event = (type: string, data: Record<string, unknown>) => ({ id: '1-0', event: type, data: { type, data } } as never);

describe('Defense coverage stream impact', () => {
  it('should collect techniques, data components and rules impacted by relationships', () => {
    const impact = collectDefenseImpact([
      event('create', { type: 'relationship', relationship_type: 'detects', extensions: { [STIX_EXT_OCTI]: { id: 'r1', type: 'detects', target_ref: AP, target_type: 'Attack-Pattern' } } }),
      event('delete', { type: 'relationship', relationship_type: 'provides', extensions: { [STIX_EXT_OCTI]: { id: 'r2', type: 'provides', source_ref: SIEM, target_ref: 'dc-1' } } }),
      event('update', { type: 'relationship', relationship_type: 'deployed-on', extensions: { [STIX_EXT_OCTI]: { id: 'r3', type: 'deployed-on', source_ref: 'rule-1', target_ref: EDR } } }),
      event('create', { type: 'relationship', relationship_type: 'uses', extensions: { [STIX_EXT_OCTI]: { id: 'r4', type: 'uses', target_ref: 'ap-other', target_type: 'Attack-Pattern' } } }),
      event('update', { type: 'indicator', extensions: { [STIX_EXT_OCTI]: { id: 'rule-2', type: 'Indicator' } } }),
    ]);
    expect(impact.full).toEqual(false);
    expect(Array.from(impact.techniqueIds)).toEqual([AP]);
    expect(Array.from(impact.dataComponentIds)).toEqual(['dc-1']);
    expect(Array.from(impact.ruleIds)).toEqual(['rule-1', 'rule-2']);
  });
  it('should ask for a full computation on platform creation and entity deletion', () => {
    expect(collectDefenseImpact([event('create', { type: 'identity', extensions: { [STIX_EXT_OCTI]: { id: 'p', type: 'SecurityPlatform' } } })]).full).toEqual(true);
    expect(collectDefenseImpact([event('delete', { type: 'x-mitre-data-component', extensions: { [STIX_EXT_OCTI]: { id: 'dc', type: 'Data-Component' } } })]).full).toEqual(true);
    expect(collectDefenseImpact([event('merge', { type: 'indicator', extensions: { [STIX_EXT_OCTI]: { id: 'i', type: 'Indicator' } } })]).full).toEqual(true);
    expect(collectDefenseImpact([event('delete', { type: 'report', extensions: { [STIX_EXT_OCTI]: { id: 'r', type: 'Report' } } })]).full).toEqual(false);
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
});
