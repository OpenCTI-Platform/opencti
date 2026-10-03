import { describe, expect, it } from 'vitest';
import '../../../../src/modules/index';
import { schemaAttributesDefinition } from '../../../../src/schema/schema-attributes';
import { ENTITY_TYPE_MALWARE } from '../../../../src/schema/stixDomainObject';
import { RELATION_USES } from '../../../../src/schema/stixCoreRelationship';
import { EditOperation } from '../../../../src/generated/graphql';
import {
  buildConflictValue,
  computeUpsertConflicts,
  conflictValueHash,
  isConflictTrackedAttribute,
  normalizeConflictValue,
} from '../../../../src/modules/provenance/provenance-conflicts';
import { computeProcedureUpsert, getProceduresDescriptionPolicy, isProceduresPreservationEnabled } from '../../../../src/modules/provenance/provenance-procedures';
import type { AssertionSource } from '../../../../src/modules/provenance/provenance-types';

const AT = '2026-10-03T08:00:00.000Z';
const incomingSource: AssertionSource = { source_id: 'connector-b', source_kind: 'connector', source_name: 'Vendor B', work_id: null };
const previousSource: AssertionSource = { source_id: 'connector-a', source_kind: 'connector', source_name: 'Vendor A', work_id: null };
const resolvePreviousOwner = async () => ({ source: previousSource, confidence: 80 });

const runConflicts = (element: Record<string, any>, updatePatch: Record<string, any>, inputs: { key: string; value: any[] }[] = []) => computeUpsertConflicts({
  type: ENTITY_TYPE_MALWARE,
  element,
  updatePatch,
  inputs: inputs.map((input) => ({ ...input, operation: EditOperation.Replace })),
  incomingSource,
  incomingConfidence: 40,
  at: AT,
  resolvePreviousOwner,
});

describe('Provenance conflicts', () => {
  it('should only track single scalar upsertable attributes', () => {
    const attribute = (name: string) => schemaAttributesDefinition.getAttribute(ENTITY_TYPE_MALWARE, name)!;
    expect(isConflictTrackedAttribute(attribute('description'))).toEqual(true);
    expect(isConflictTrackedAttribute(attribute('is_family'))).toEqual(true);
    expect(isConflictTrackedAttribute(attribute('confidence'))).toEqual(false);
    expect(isConflictTrackedAttribute(attribute('modified'))).toEqual(false);
    expect(isConflictTrackedAttribute(attribute('aliases'))).toEqual(false);
    expect(isConflictTrackedAttribute(attribute('x_opencti_assertions'))).toEqual(false);
  });

  it('should normalize values before comparing them', () => {
    const description = schemaAttributesDefinition.getAttribute(ENTITY_TYPE_MALWARE, 'description')!;
    const firstSeen = schemaAttributesDefinition.getAttribute(ENTITY_TYPE_MALWARE, 'first_seen')!;
    expect(normalizeConflictValue(description, '  text ')).toEqual('text');
    expect(normalizeConflictValue(firstSeen, new Date(AT))).toEqual(AT);
    expect(conflictValueHash('description', 'a')).not.toEqual(conflictValueHash('name', 'a'));
  });

  it('should keep the incoming value when it lost the confidence resolution', async () => {
    const { conflictsAdd, conflictsRemove } = await runConflicts({ description: 'from A' }, { description: 'from B' });
    expect(conflictsRemove).toEqual([]);
    expect(conflictsAdd).toHaveLength(1);
    expect(conflictsAdd[0].field).toEqual('description');
    expect(conflictsAdd[0].value).toMatchObject({ display: 'from B', value: JSON.stringify('from B'), source_id: 'connector-b', confidence: 40, last_asserted_at: AT });
  });

  it('should keep the previous value when the incoming value won', async () => {
    const { conflictsAdd, conflictsRemove } = await runConflicts({ description: 'from A' }, { description: 'from B' }, [{ key: 'description', value: ['from B'] }]);
    expect(conflictsAdd).toHaveLength(1);
    expect(conflictsAdd[0].value).toMatchObject({ display: 'from A', source_id: 'connector-a', confidence: 80 });
    expect(conflictsRemove).toEqual([{ field: 'description', value_hash: conflictValueHash('description', 'from B') }]);
  });

  it('should not report a conflict when values agree or one side is empty', async () => {
    const same = await runConflicts({ description: 'same' }, { description: ' same ' });
    expect(same.conflictsAdd).toEqual([]);
    expect(same.conflictsRemove).toEqual([{ field: 'description', value_hash: conflictValueHash('description', 'same') }]);
    const empty = await runConflicts({ description: '' }, { description: 'new' });
    expect(empty.conflictsAdd).toEqual([]);
    const missing = await runConflicts({ description: 'current' }, { description: '   ' });
    expect(missing.conflictsAdd).toEqual([]);
  });

  it('should never track fields aligned by the upsert itself', async () => {
    const { conflictsAdd } = await runConflicts({ confidence: 80, modified: AT }, { confidence: 10, modified: '2020-01-01T00:00:00.000Z' });
    expect(conflictsAdd).toEqual([]);
  });

  it('should keep large values as display only', () => {
    const description = schemaAttributesDefinition.getAttribute(ENTITY_TYPE_MALWARE, 'description')!;
    const value = buildConflictValue(description, 'x'.repeat(40000), incomingSource, 10, AT);
    expect(value.value).toBeNull();
    expect(value.display.length).toBeLessThan(600);
  });
});

describe('Provenance procedures', () => {
  const base = { source: incomingSource, previousSource, at: AT, inputs: [] };

  it('should be enabled with the longest policy by default', () => {
    expect(isProceduresPreservationEnabled(undefined)).toEqual(true);
    expect(isProceduresPreservationEnabled({ platform_procedures_preservation: false })).toEqual(false);
    expect(getProceduresDescriptionPolicy(undefined)).toEqual('longest');
    expect(getProceduresDescriptionPolicy({ platform_procedures_description_policy: 'most_recent' })).toEqual('most_recent');
  });

  it('should preserve a new procedure and keep the longest description', () => {
    const result = computeProcedureUpsert({
      ...base,
      element: { description: 'Uses spearphishing attachments with macro documents', procedures: [{ text: 'Uses spearphishing attachments with macro documents', source_id: 'connector-a', last_asserted_at: AT }] },
      incomingDescription: 'Phishing',
      policy: 'longest',
      isConfidenceMatch: true,
    });
    expect(result.proceduresAdd).toEqual([{ text: 'Phishing', source_id: 'connector-b', last_asserted_at: AT }]);
    expect(result.inputs).toEqual([]);
  });

  it('should take the most recent description when configured', () => {
    const result = computeProcedureUpsert({
      ...base,
      element: { description: 'Long existing procedure', procedures: [{ text: 'Long existing procedure', source_id: 'connector-a', last_asserted_at: AT }] },
      incomingDescription: 'Short',
      policy: 'most_recent',
      isConfidenceMatch: true,
    });
    expect(result.inputs).toEqual([{ key: 'description', value: ['Short'], operation: EditOperation.Replace }]);
  });

  it('should not change the description without enough confidence', () => {
    const result = computeProcedureUpsert({
      ...base,
      element: { description: 'Short', procedures: [{ text: 'Short', source_id: 'connector-a', last_asserted_at: AT }] },
      incomingDescription: 'A much longer procedure description',
      policy: 'longest',
      isConfidenceMatch: false,
      inputs: [{ key: 'description', value: ['A much longer procedure description'], operation: EditOperation.Replace }],
    });
    expect(result.inputs).toEqual([]);
    expect(result.proceduresAdd).toHaveLength(1);
  });

  it('should seed the existing description of relationships created before preservation', () => {
    const result = computeProcedureUpsert({
      ...base,
      element: { description: 'Legacy description', procedures: [], created_at: AT },
      incomingDescription: 'Another procedure',
      policy: 'longest',
      isConfidenceMatch: true,
    });
    expect(result.proceduresAdd).toEqual([
      { text: 'Legacy description', source_id: 'connector-a', last_asserted_at: AT },
      { text: 'Another procedure', source_id: 'connector-b', last_asserted_at: AT },
    ]);
  });

  it('should register procedures as a side-channel attribute', () => {
    const definition = schemaAttributesDefinition.getAttribute(RELATION_USES, 'procedures');
    expect(definition?.update).toEqual(false);
  });
});
