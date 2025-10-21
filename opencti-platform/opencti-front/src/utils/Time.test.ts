import { describe, expect, it } from 'vitest';
import { dateFiltersValueForDisplay } from './Time';

describe('Time utils', () => {
  describe('dateFiltersValueForDisplay', () => {
    it('should convert a date filter value to a date value for display', () => {
      expect(dateFiltersValueForDisplay('2025-10-02T22:00:00.000Z', 'lt')).toEqual('2025-10-02T22:00:00.000Z');
      expect(dateFiltersValueForDisplay('2025-10-02T22:00:00.000Z', 'lte')).toEqual(new Date('2025-10-01T22:00:00.000Z'));
      expect(dateFiltersValueForDisplay('2025-10-02T22:00:00.000Z', 'gte')).toEqual('2025-10-02T22:00:00.000Z');
      expect(dateFiltersValueForDisplay('2025-10-02T22:00:00.000Z', 'gt')).toEqual(new Date('2025-10-01T22:00:00.000Z'));
    });
  });
});
