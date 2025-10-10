import { describe, it, expect } from 'vitest';
import { getNodes } from './connection';

describe('Function: getNodes()', () => {
  it('should return empty array if no data', () => {
    expect(getNodes(undefined)).toEqual([]);
    expect(getNodes(null)).toEqual([]);
  });

  it('should return empty array if data is no edges', () => {
    expect(getNodes({ edges: undefined })).toEqual([]);
    expect(getNodes({ edges: null })).toEqual([]);
    expect(getNodes({ edges: [] })).toEqual([]);
  });

  it('should return list of non empty nodes', () => {
    const nodes = [
      { node: null },
      { node: 'hello' },
      { node: 'there' },
      { node: undefined },
    ];
    expect(getNodes({ edges: nodes })).toEqual(['hello', 'there']);
  });
});
