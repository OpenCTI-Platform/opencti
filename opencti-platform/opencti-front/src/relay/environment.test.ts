import { describe, expect, it } from 'vitest';
import { getDataID } from './environment';

describe('getDataID', () => {
  it('does not collide a Connector with a Synchronizer sharing the same id (sync twin connector)', () => {
    const id = '3753c425-0000-4000-8000-000000000000';
    expect(getDataID({ id }, 'Connector')).not.toBe(getDataID({ id }, 'Synchronizer'));
  });

  it('keeps the raw id for other types', () => {
    expect(getDataID({ id: 'abc' }, 'Synchronizer')).toBe('abc');
  });
});
