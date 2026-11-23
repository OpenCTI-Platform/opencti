import { describe, expect, it } from 'vitest';
import { FilterMode, FilterOperator, PirType } from '../../../../src/generated/graphql';
import {
  LEGACY_THREAT_LANDSCAPE_TYPES,
  legacyCriterionId,
  legacyGroupId,
  legacyPirScore,
  legacyPirToRequirement,
  legacyWeightPoints,
  splitLegacyCriterionFilters,
} from '../../../../src/modules/intelligenceRequirement/intelligenceRequirement-legacy';

const FRANCE = '9b8fd9c3-1ca3-41c2-be13-730f35b166b2';
const HEALTHCARE = '5a2c3f0e-8a4b-4f0b-9a55-2f3b1c7d9e10';

const criterion = (weight: number, relationshipType: string, targetIds: string[], extra: any[] = []) => ({
  weight,
  filters: {
    mode: FilterMode.And,
    filterGroups: [],
    filters: [
      { key: ['entity_type'], values: [relationshipType], operator: FilterOperator.Eq, mode: FilterMode.Or },
      { key: ['toId'], values: targetIds, operator: FilterOperator.Eq, mode: FilterMode.Or },
      ...extra,
    ],
  },
});

const confidenceAbove80 = { mode: FilterMode.And, filterGroups: [], filters: [{ key: ['confidence'], values: ['80'], operator: FilterOperator.Gt, mode: FilterMode.Or }] };
const noFilters = { mode: FilterMode.And, filterGroups: [], filters: [] };

describe('Legacy PIR to intelligence requirement', () => {
  it('should split a criterion into relationship types, targets and the rest', () => {
    const { relationshipTypes, targetIds, sourceTypes, rest } = splitLegacyCriterionFilters(criterion(1, 'targets', [FRANCE]).filters);
    expect(relationshipTypes).toEqual(['targets']);
    expect(targetIds).toEqual([FRANCE]);
    expect(sourceTypes).toEqual([]);
    expect(rest).toBeNull();
  });

  it('should keep the filters it does not read as relationship filters', () => {
    const extra = { key: ['confidence'], values: ['50'], operator: FilterOperator.Gt, mode: FilterMode.Or };
    const { rest } = splitLegacyCriterionFilters(criterion(1, 'targets', [FRANCE], [extra]).filters);
    expect(rest?.filters).toEqual([extra]);
  });

  it('should keep an OR group whole', () => {
    const group = { ...criterion(1, 'targets', [FRANCE]).filters, mode: FilterMode.Or };
    const split = splitLegacyCriterionFilters(group);
    expect(split.relationshipTypes).toEqual([]);
    expect(split.rest).toEqual(group);
  });

  it('should build one list group, one incoming graph criterion and one weight rule per legacy criterion', () => {
    const config = legacyPirToRequirement({
      name: 'Threats on France',
      description: 'Who targets France',
      pir_type: PirType.ThreatLandscape,
      pir_rescan_days: 30,
      pir_filters: confidenceAbove80,
      pir_criteria: [criterion(2, 'targets', [FRANCE]), criterion(1, 'targets', [HEALTHCARE])],
    });
    expect(config.ir_subject_groups.map((g) => ({ id: g.id, kind: g.kind, entity_ids: g.entity_ids }))).toEqual([
      { id: legacyGroupId(0), kind: 'list', entity_ids: [FRANCE] },
      { id: legacyGroupId(1), kind: 'list', entity_ids: [HEALTHCARE] },
    ]);
    const [first] = config.ir_scope_criteria;
    expect(first.kind).toEqual('graph');
    expect(first.direction).toEqual('incoming');
    expect(first.from_group_ids).toEqual([legacyGroupId(0)]);
    expect(first.relationship_types).toEqual(['targets']);
    expect(first.target_types).toEqual(LEGACY_THREAT_LANDSCAPE_TYPES);
    expect(first.mode).toEqual('auto');
    expect(JSON.parse(first.relationship_filters as string)).toEqual(confidenceAbove80);
    expect(config.ir_relevance_rules.map((r) => [r.applies_to_criterion_id, r.points])).toEqual([[legacyCriterionId(0), 67], [legacyCriterionId(1), 33]]);
    expect(config.ir_rescan_days).toEqual(30);
    expect(config.ir_question).toEqual('Who targets France');
  });

  it('should not restrict the source types of a custom PIR', () => {
    const config = legacyPirToRequirement({ name: 'Custom', pir_type: PirType.ThreatCustom, pir_rescan_days: 0, pir_filters: noFilters, pir_criteria: [criterion(1, 'targets', [FRANCE])] });
    expect(config.ir_scope_criteria[0].target_types).toEqual([]);
    expect(config.ir_scope_criteria[0].relationship_filters).toBeNull();
    expect(config.ir_question).toEqual('Custom');
  });

  it('should be deterministic, so a migration run twice builds the same configuration', () => {
    const pir = { name: 'P', pir_type: PirType.ThreatLandscape, pir_rescan_days: 1, pir_filters: confidenceAbove80, pir_criteria: [criterion(3, 'targets', [FRANCE])] };
    expect(legacyPirToRequirement(pir)).toEqual(legacyPirToRequirement(pir));
  });
});

describe('Legacy PIR score', () => {
  it('should give the matched weights over the sum of the weights, rounded once', () => {
    expect(legacyPirScore([2, 1], [legacyCriterionId(0)])).toEqual(67);
    expect(legacyPirScore([2, 1], [legacyCriterionId(1)])).toEqual(33);
    expect(legacyPirScore([2, 1], [legacyCriterionId(0), legacyCriterionId(1)])).toEqual(100);
    expect(legacyPirScore([1, 1, 1], [legacyCriterionId(0), legacyCriterionId(1)])).toEqual(67);
  });

  it('should count a criterion matched twice once and ignore unknown criteria', () => {
    expect(legacyPirScore([1, 3], [legacyCriterionId(1), legacyCriterionId(1), 'other'])).toEqual(75);
  });

  it('should give 0 without weight', () => {
    expect(legacyPirScore([], [])).toEqual(0);
    expect(legacyWeightPoints([0, 0])).toEqual([0, 0]);
  });
});
