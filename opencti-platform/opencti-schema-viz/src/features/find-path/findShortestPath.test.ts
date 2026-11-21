import { describe, expect, it } from 'vitest';
import { buildFixtureSchema } from '../../test/fixtures';
import { findShortestPath } from './findShortestPath';

const schema = buildFixtureSchema();

describe('findShortestPath', () => {
  it('follows relations backwards when undirected', () => {
    const path = findShortestPath(schema, 'Sector', 'Tool');
    expect(path?.typeIds).toEqual(['Sector', 'Malware', 'Tool']);
    expect(path?.steps.map((step) => step.direction)).toEqual(['in', 'out']);
  });

  it('respects relation direction when directed', () => {
    expect(findShortestPath(schema, 'Sector', 'Tool', { directed: true, includeRefs: false })).toBeNull();
    expect(findShortestPath(schema, 'Malware', 'Sector', { directed: true, includeRefs: false })?.steps).toHaveLength(1);
  });

  it('reaches subtypes of an abstract target and reports the declared type', () => {
    const path = findShortestPath(schema, 'Tool', 'Threat-Actor-Individual', { directed: true, includeRefs: false });
    expect(path?.steps).toEqual([expect.objectContaining({ toTypeId: 'Threat-Actor-Individual', viaTypeId: 'Threat-Actor' })]);
  });

  it('returns a zero-step path for the same type and null for unknown types', () => {
    expect(findShortestPath(schema, 'Tool', 'Tool')?.steps).toEqual([]);
    expect(findShortestPath(schema, 'Tool', 'Nope')).toBeNull();
  });
});
