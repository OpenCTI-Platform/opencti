import { describe, expect, it } from 'vitest';
import { analyseTechniqueUsage } from './ttpAnalyser';
import type { ObjectToParse } from '../../../../../components/graph/utils/useGraphParser';

const ap = (id: string, name = id) => (
  { id, entity_type: 'Attack-Pattern', name, parent_types: [] } as unknown as ObjectToParse
);

const entity = (id: string, entity_type: string, name: string | undefined = id) => (
  { id, entity_type, name, parent_types: [] } as unknown as ObjectToParse
);

const rel = (id: string, relationship_type: string, fromId: string, toId: string, fromType = 'Unknown', toType = 'Unknown') => ({
  id,
  entity_type: relationship_type === 'object' ? 'stix-ref-relationship' : 'stix-core-relationship',
  relationship_type,
  parent_types: [],
  from: { id: fromId, entity_type: fromType },
  to: { id: toId, entity_type: toType },
}) as unknown as ObjectToParse;

const IS_A = entity('is-a', 'Intrusion-Set', 'IS-A');

describe('analyseTechniqueUsage', () => {
  it('scores an attack pattern used by an intrusion set', () => {
    const usage = analyseTechniqueUsage([
      ap('ap1'),
      IS_A,
      rel('r1', 'uses', 'is-a', 'ap1', 'Intrusion-Set', 'Attack-Pattern'),
    ]);
    expect(usage.get('ap1')?.attackPatternId).toBe('ap1');
    expect(usage.get('ap1')?.score).toBe(1);
    expect(usage.get('ap1')?.linkedEntities).toEqual([{ id: 'is-a', name: 'IS-A', entity_type: 'Intrusion-Set' }]);
    expect(usage.size).toBe(1);
  });

  it('scores an attack pattern that uses a tool', () => {
    const usage = analyseTechniqueUsage([
      ap('ap1'),
      entity('tool-1', 'Tool', 'Tool-1'),
      rel('r1', 'uses', 'ap1', 'tool-1', 'Attack-Pattern', 'Tool'),
    ]);
    expect(usage.get('ap1')?.linkedEntities.map((e) => e.name)).toEqual(['Tool-1']);
  });

  it('scores an attack pattern indicated by an indicator', () => {
    const usage = analyseTechniqueUsage([
      ap('ap1'),
      entity('ind', 'Indicator', 'Ind'),
      rel('r1', 'indicates', 'ind', 'ap1', 'Indicator', 'Attack-Pattern'),
    ]);
    expect(usage.get('ap1')?.score).toBe(1);
    expect(usage.get('ap1')?.linkedEntities.map((e) => e.id)).toEqual(['ind']);
  });

  it('does not score an attack pattern that indicates something', () => {
    const usage = analyseTechniqueUsage([
      ap('ap1'),
      entity('x', 'Malware', 'X'),
      rel('r1', 'indicates', 'ap1', 'x', 'Attack-Pattern', 'Malware'),
    ]);
    expect(usage.size).toBe(0);
  });

  it('scores an attack pattern with the container that holds it', () => {
    const usage = analyseTechniqueUsage([
      ap('ap1'),
      entity('report', 'Report', 'Report'),
      rel('r1', 'object', 'report', 'ap1', 'Report', 'Attack-Pattern'),
    ]);
    expect(usage.get('ap1')?.linkedEntities).toEqual([{ id: 'report', name: 'Report', entity_type: 'Report' }]);
  });

  it('does not score a container held by an attack pattern', () => {
    const usage = analyseTechniqueUsage([
      ap('ap1'),
      entity('report', 'Report', 'Report'),
      rel('r1', 'object', 'ap1', 'report', 'Attack-Pattern', 'Report'),
    ]);
    expect(usage.size).toBe(0);
  });

  it('counts a distinct entity once even with several relationships', () => {
    const usage = analyseTechniqueUsage([
      ap('ap1'),
      IS_A,
      rel('r1', 'uses', 'is-a', 'ap1', 'Intrusion-Set', 'Attack-Pattern'),
      rel('r2', 'uses', 'is-a', 'ap1', 'Intrusion-Set', 'Attack-Pattern'),
    ]);
    expect(usage.get('ap1')?.score).toBe(1);
    expect(usage.get('ap1')?.linkedEntities).toHaveLength(1);
  });

  it('counts distinct entities across rules', () => {
    const usage = analyseTechniqueUsage([
      ap('ap1'),
      IS_A,
      entity('ind', 'Indicator'),
      entity('report', 'Report'),
      rel('r1', 'uses', 'is-a', 'ap1'),
      rel('r2', 'indicates', 'ind', 'ap1'),
      rel('r3', 'object', 'report', 'ap1'),
    ]);
    expect(usage.get('ap1')?.score).toBe(3);
  });

  it('ignores a relationship whose entity is not in rawObjects', () => {
    const usage = analyseTechniqueUsage([
      ap('ap1'),
      rel('r1', 'uses', 'is-a', 'ap1', 'Intrusion-Set', 'Attack-Pattern'),
    ]);
    expect(usage.size).toBe(0);
  });

  it('ignores an entity whose relationship is not in rawObjects', () => {
    const usage = analyseTechniqueUsage([ap('ap1'), IS_A]);
    expect(usage.size).toBe(0);
  });

  it.each(['mitigates', 'should-cover', 'has-covered', 'related-to', 'subtechnique-of'])(
    'gives no score for %s',
    (type) => {
      const usage = analyseTechniqueUsage([
        ap('ap1'),
        IS_A,
        rel('r1', type, 'is-a', 'ap1', 'Intrusion-Set', 'Attack-Pattern'),
        rel('r2', type, 'ap1', 'is-a', 'Attack-Pattern', 'Intrusion-Set'),
      ]);
      expect(usage.size).toBe(0);
    },
  );

  it('scores a sub-technique only, with no entry for the parent', () => {
    const usage = analyseTechniqueUsage([
      ap('ap1'),
      ap('ap1.001'),
      IS_A,
      rel('sub', 'subtechnique-of', 'ap1.001', 'ap1', 'Attack-Pattern', 'Attack-Pattern'),
      rel('r1', 'uses', 'is-a', 'ap1.001', 'Intrusion-Set', 'Attack-Pattern'),
    ]);
    expect(usage.get('ap1.001')?.score).toBe(1);
    expect(usage.has('ap1')).toBe(false);
  });

  it('scores a parent and a sub-technique independently', () => {
    const usage = analyseTechniqueUsage([
      ap('ap1'),
      ap('ap1.001'),
      IS_A,
      rel('r1', 'uses', 'is-a', 'ap1'),
      rel('r2', 'uses', 'is-a', 'ap1.001'),
    ]);
    expect(usage.get('ap1')?.score).toBe(1);
    expect(usage.get('ap1.001')?.score).toBe(1);
  });

  it('skips a relationship with a missing from or to without throwing', () => {
    const noFrom = { ...rel('r1', 'uses', 'is-a', 'ap1'), from: undefined } as unknown as ObjectToParse;
    const noTo = { ...rel('r2', 'uses', 'is-a', 'ap1'), to: undefined } as unknown as ObjectToParse;
    const nullEnds = { ...rel('r3', 'uses', 'is-a', 'ap1'), from: null, to: null } as unknown as ObjectToParse;
    const objects = [ap('ap1'), IS_A, noFrom, noTo, nullEnds];
    expect(() => analyseTechniqueUsage(objects)).not.toThrow();
    expect(analyseTechniqueUsage(objects).size).toBe(0);
  });

  it('skips a relationship whose end is itself a relationship', () => {
    const objects = [
      ap('ap1'),
      IS_A,
      entity('tool-1', 'Tool'),
      rel('base', 'uses', 'is-a', 'tool-1'),
      rel('r1', 'uses', 'base', 'ap1', 'uses', 'Attack-Pattern'),
      rel('r2', 'uses', 'ap1', 'base', 'Attack-Pattern', 'uses'),
    ];
    expect(() => analyseTechniqueUsage(objects)).not.toThrow();
    expect(analyseTechniqueUsage(objects).size).toBe(0);
  });

  it('uses the observable value when an entity has no name', () => {
    const observable = { id: 'obs', entity_type: 'IPv4-Addr', observable_value: '1.2.3.4', parent_types: [] } as unknown as ObjectToParse;
    const usage = analyseTechniqueUsage([
      ap('ap1'),
      observable,
      rel('r1', 'uses', 'obs', 'ap1', 'IPv4-Addr', 'Attack-Pattern'),
    ]);
    expect(usage.get('ap1')?.linkedEntities[0].name).toBe('1.2.3.4');
  });

  it('analyses 5,000 objects in under 50 ms', () => {
    const objects: ObjectToParse[] = [];
    for (let i = 0; i < 1000; i += 1) objects.push(ap(`ap-${i}`));
    for (let i = 0; i < 2000; i += 1) objects.push(entity(`e-${i}`, 'Malware', `Malware ${i}`));
    for (let i = 0; i < 2000; i += 1) {
      objects.push(rel(`r-${i}`, 'uses', `e-${i}`, `ap-${i % 1000}`, 'Malware', 'Attack-Pattern'));
    }
    const start = performance.now();
    const usage = analyseTechniqueUsage(objects);
    const elapsed = performance.now() - start;
    expect(usage.size).toBe(1000);
    expect(usage.get('ap-0')?.score).toBe(2);
    expect(elapsed).toBeLessThan(50);
  });
});
