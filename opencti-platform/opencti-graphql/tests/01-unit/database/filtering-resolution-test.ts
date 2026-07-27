import { describe, expect, it } from 'vitest';
import { FilterMode, FilterOperator } from '../../../src/generated/graphql';
import { stripEventContextFilters } from '../../../src/utils/filtering/filtering-resolution';

describe('filtering-resolution', () => {
  describe('stripEventContextFilters', () => {
    it('should remove has_changed filters', () => {
      const filterGroup = {
        mode: FilterMode.And,
        filters: [
          { mode: FilterMode.Or, key: ['score'], operator: FilterOperator.HasChanged, values: [] },
          { mode: FilterMode.Or, key: ['score'], operator: FilterOperator.Gt, values: ['50'] },
        ],
        filterGroups: [],
      };

      const result = stripEventContextFilters(filterGroup);
      expect(result).toEqual({
        mode: FilterMode.And,
        filters: [
          { mode: FilterMode.Or, key: ['score'], operator: FilterOperator.Gt, values: ['50'] },
        ],
        filterGroups: [],
      });
    });

    it('should remove not_has_changed filters', () => {
      const filterGroup = {
        mode: FilterMode.And,
        filters: [
          { mode: FilterMode.Or, key: ['confidence'], operator: FilterOperator.NotHasChanged, values: [] },
          { mode: FilterMode.Or, key: ['entity_type'], operator: FilterOperator.Eq, values: ['Report'] },
        ],
        filterGroups: [],
      };

      const result = stripEventContextFilters(filterGroup);
      expect(result).toEqual({
        mode: FilterMode.And,
        filters: [
          { mode: FilterMode.Or, key: ['entity_type'], operator: FilterOperator.Eq, values: ['Report'] },
        ],
        filterGroups: [],
      });
    });

    it('should return null when all filters are event-context operators', () => {
      const filterGroup = {
        mode: FilterMode.And,
        filters: [
          { mode: FilterMode.Or, key: ['score'], operator: FilterOperator.HasChanged, values: [] },
          { mode: FilterMode.Or, key: ['confidence'], operator: FilterOperator.NotHasChanged, values: [] },
        ],
        filterGroups: [],
      };

      const result = stripEventContextFilters(filterGroup);
      expect(result).toBeNull();
    });

    it('should keep non-event-context filters untouched', () => {
      const filterGroup = {
        mode: FilterMode.And,
        filters: [
          { mode: FilterMode.Or, key: ['score'], operator: FilterOperator.Gt, values: ['50'] },
          { mode: FilterMode.Or, key: ['entity_type'], operator: FilterOperator.Eq, values: ['Report'] },
        ],
        filterGroups: [],
      };

      const result = stripEventContextFilters(filterGroup);
      expect(result).toEqual(filterGroup);
    });

    it('should strip recursively in nested filter groups', () => {
      const filterGroup = {
        mode: FilterMode.And,
        filters: [],
        filterGroups: [
          {
            mode: FilterMode.Or,
            filters: [
              { mode: FilterMode.Or, key: ['score'], operator: FilterOperator.HasChanged, values: [] },
              { mode: FilterMode.Or, key: ['score'], operator: FilterOperator.Gt, values: ['50'] },
            ],
            filterGroups: [],
          },
          {
            mode: FilterMode.And,
            filters: [
              { mode: FilterMode.Or, key: ['confidence'], operator: FilterOperator.NotHasChanged, values: [] },
            ],
            filterGroups: [],
          },
        ],
      };

      const result = stripEventContextFilters(filterGroup);
      // Second nested group becomes empty → removed. First nested group keeps the Gt filter.
      expect(result).toEqual({
        mode: FilterMode.And,
        filters: [],
        filterGroups: [
          {
            mode: FilterMode.Or,
            filters: [
              { mode: FilterMode.Or, key: ['score'], operator: FilterOperator.Gt, values: ['50'] },
            ],
            filterGroups: [],
          },
        ],
      });
    });

    it('should return null when nested groups all become empty after stripping', () => {
      const filterGroup = {
        mode: FilterMode.And,
        filters: [],
        filterGroups: [
          {
            mode: FilterMode.Or,
            filters: [
              { mode: FilterMode.Or, key: ['score'], operator: FilterOperator.HasChanged, values: [] },
            ],
            filterGroups: [],
          },
        ],
      };

      const result = stripEventContextFilters(filterGroup);
      expect(result).toBeNull();
    });
  });
});
