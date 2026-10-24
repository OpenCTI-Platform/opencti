import { describe, expect, it } from 'vitest';
import { FilterMode, type IntelligenceRequirementInput } from '../../../../src/generated/graphql';
import {
  IR_DEFAULT_THRESHOLDS,
  parseIntelligenceRequirement,
  serializeIntelligenceRequirementInput,
} from '../../../../src/modules/intelligenceRequirement/intelligenceRequirement-config';
import type { BasicStoreEntityIntelligenceRequirement } from '../../../../src/modules/intelligenceRequirement/intelligenceRequirement-types';

const kevFilter = { mode: FilterMode.And, filterGroups: [], filters: [{ key: ['x_opencti_cisa_kev'], values: ['true'] }] };

// The Deepwatch-like requirement of the mockup: vulnerabilities exploited by ransomware targeting Europe
const validInput = (): IntelligenceRequirementInput => ({
  name: 'Exploitable vulnerabilities used by ransomware against Europe',
  ir_question: 'Which vulnerabilities are exploited by ransomware operations targeting Europe?',
  ir_priority: 'critical' as IntelligenceRequirementInput['ir_priority'],
  ir_kiqs: [{ id: 'kiq-1', text: 'Which vulnerabilities do they exploit?', criteria_ids: ['c1'] }],
  ir_subject_groups: [
    { id: 'g-ransomware', name: 'Ransomware', kind: 'filter' as never, role: 'entry' as never, filters: { mode: FilterMode.And, filterGroups: [], filters: [{ key: ['entity_type'], values: ['Malware'] }] } },
    { id: 'g-region', name: 'Region', kind: 'list' as never, role: 'context' as never, entity_ids: ['europe-id'] },
    { id: 'g-keywords', name: 'Keywords', kind: 'keywords' as never, role: 'entry' as never, keywords: [' fortios ', '', 'ssl-vpn'] },
  ],
  ir_scope_criteria: [
    { id: 'c1', kind: 'graph' as never, from_group_ids: ['g-ransomware'], relationship_types: ['exploits'], direction: 'outgoing' as never, target_types: ['Vulnerability'], mode: 'auto' as never },
    { id: 'c2', kind: 'keywords' as never, from_group_ids: ['g-keywords'], target_types: ['Vulnerability'], mode: 'propose' as never },
  ],
  ir_relevance_rules: [
    { id: 'r1', name: 'In CISA KEV', applies_to_types: ['Vulnerability'], filters: kevFilter, points: 30 },
    {
      id: 'r0',
      name: 'Exploited by a threat targeting Europe',
      applies_to_types: ['Vulnerability'],
      applies_to_criterion_id: 'c1',
      path_condition: { relationship_types: ['exploits'], direction: 'incoming' as never, target_relationship_type: 'targets', target_ids: ['europe-id'] },
      points: 0,
      required: true,
    },
  ],
});

describe('Intelligence requirement configuration', () => {
  it('should serialize a valid configuration with defaults', () => {
    const attributes = serializeIntelligenceRequirementInput(validInput());
    expect(attributes.ir_status).toEqual('active');
    expect(attributes.ir_thresholds).toEqual(IR_DEFAULT_THRESHOLDS);
    const groups = JSON.parse(attributes.ir_subject_groups);
    expect(groups[2].keywords).toEqual(['fortios', 'ssl-vpn']);
    expect(JSON.parse(groups[0].filters).filters[0].values).toEqual(['Malware']);
    const criteria = JSON.parse(attributes.ir_scope_criteria);
    expect(criteria[1].keyword_fields).toEqual(['name', 'description', 'content']);
    const rules = JSON.parse(attributes.ir_relevance_rules);
    expect(rules[0]).toMatchObject({ required: false, enabled: true, applies_to_criterion_id: null });
    expect(rules[1]).toMatchObject({ required: true, path_condition: { target_relationship_type: 'targets' } });
  });

  it('should parse back the stored blocks', () => {
    const attributes = serializeIntelligenceRequirementInput(validInput());
    const parsed = parseIntelligenceRequirement(attributes as unknown as BasicStoreEntityIntelligenceRequirement);
    expect(parsed.ir_subject_groups.map((g) => g.id)).toEqual(['g-ransomware', 'g-region', 'g-keywords']);
    expect(parsed.ir_scope_criteria[0].relationship_types).toEqual(['exploits']);
    expect(parsed.ir_relevance_rules).toHaveLength(2);
  });

  it('should reject a criterion that references an unknown subject group', () => {
    const input = validInput();
    input.ir_scope_criteria[0].from_group_ids = ['unknown'];
    expect(() => serializeIntelligenceRequirementInput(input)).toThrowError('Scope criterion references an unknown subject group');
  });

  it('should reject a graph criterion without relationship type', () => {
    const input = validInput();
    input.ir_scope_criteria[0].relationship_types = [];
    expect(() => serializeIntelligenceRequirementInput(input)).toThrowError('A graph criterion needs at least one relationship type');
  });

  it('should reject a keywords criterion without keywords group', () => {
    const input = validInput();
    input.ir_scope_criteria[1].from_group_ids = ['g-ransomware'];
    expect(() => serializeIntelligenceRequirementInput(input)).toThrowError('A keywords criterion needs a keywords subject group');
  });

  it('should reject a rule that references an unknown criterion', () => {
    const input = validInput();
    input.ir_relevance_rules![1].applies_to_criterion_id = 'c9';
    expect(() => serializeIntelligenceRequirementInput(input)).toThrowError('Relevance rule references an unknown scope criterion');
  });

  it('should reject duplicate ids', () => {
    const input = validInput();
    input.ir_scope_criteria[1].id = 'c1';
    expect(() => serializeIntelligenceRequirementInput(input)).toThrowError('Duplicate id in scope');
  });

  it('should reject an empty list group', () => {
    const input = validInput();
    input.ir_subject_groups[1].entity_ids = [];
    expect(() => serializeIntelligenceRequirementInput(input)).toThrowError('A list subject group needs at least one entity');
  });
});
