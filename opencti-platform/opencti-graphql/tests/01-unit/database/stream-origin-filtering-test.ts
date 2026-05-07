import { describe, expect, it } from 'vitest';
import { isOriginMatchFilterGroup, validateFilterGroupForStreamOriginMatch } from '../../../src/utils/filtering/filtering-stream-origin/stream-origin-filtering';
import type { FilterGroup } from '../../../src/generated/graphql';

const buildEvent = (origin?: { user_id?: string; group_ids?: string[]; organization_ids?: string[] }) => ({
  type: 'create',
  scope: 'external',
  origin,
  data: { id: 'report--abc', type: 'report' },
});

const emptyFilterGroup = { mode: 'and', filters: [], filterGroups: [] } as unknown as FilterGroup;

describe('Stream origin filtering', () => {
  describe('isOriginMatchFilterGroup', () => {
    it('returns true when filter group is undefined', () => {
      expect(isOriginMatchFilterGroup(buildEvent({ user_id: 'user-1' }))).toEqual(true);
    });

    it('returns true when filter group is empty', () => {
      expect(isOriginMatchFilterGroup(buildEvent({ user_id: 'user-1' }), emptyFilterGroup)).toEqual(true);
    });

    it('returns true when origin user_id matches a single-value members_user filter', () => {
      const filterGroup = {
        mode: 'and',
        filters: [{ key: ['members_user'], mode: 'or', operator: 'eq', values: ['user-1'] }],
        filterGroups: [],
      } as unknown as FilterGroup;
      expect(isOriginMatchFilterGroup(buildEvent({ user_id: 'user-1' }), filterGroup)).toEqual(true);
      expect(isOriginMatchFilterGroup(buildEvent({ user_id: 'user-2' }), filterGroup)).toEqual(false);
    });

    it('returns true when at least one origin group_id matches a members_group filter', () => {
      const filterGroup = {
        mode: 'and',
        filters: [{ key: ['members_group'], mode: 'or', operator: 'eq', values: ['group-a', 'group-b'] }],
        filterGroups: [],
      } as unknown as FilterGroup;
      expect(isOriginMatchFilterGroup(buildEvent({ group_ids: ['group-a'] }), filterGroup)).toEqual(true);
      expect(isOriginMatchFilterGroup(buildEvent({ group_ids: ['group-z'] }), filterGroup)).toEqual(false);
      expect(isOriginMatchFilterGroup(buildEvent({ group_ids: [] }), filterGroup)).toEqual(false);
      expect(isOriginMatchFilterGroup(buildEvent(undefined), filterGroup)).toEqual(false);
    });

    it('returns true when at least one origin organization_id matches a members_organization filter', () => {
      const filterGroup = {
        mode: 'and',
        filters: [{ key: ['members_organization'], mode: 'or', operator: 'eq', values: ['org-1'] }],
        filterGroups: [],
      } as unknown as FilterGroup;
      expect(isOriginMatchFilterGroup(buildEvent({ organization_ids: ['org-1', 'org-2'] }), filterGroup)).toEqual(true);
      expect(isOriginMatchFilterGroup(buildEvent({ organization_ids: ['org-9'] }), filterGroup)).toEqual(false);
    });

    it('combines several origin filters with AND', () => {
      const filterGroup = {
        mode: 'and',
        filters: [
          { key: ['members_user'], mode: 'or', operator: 'eq', values: ['user-1'] },
          { key: ['members_group'], mode: 'or', operator: 'eq', values: ['group-a'] },
        ],
        filterGroups: [],
      } as unknown as FilterGroup;
      expect(isOriginMatchFilterGroup(buildEvent({ user_id: 'user-1', group_ids: ['group-a'] }), filterGroup)).toEqual(true);
      expect(isOriginMatchFilterGroup(buildEvent({ user_id: 'user-1', group_ids: ['group-b'] }), filterGroup)).toEqual(false);
      expect(isOriginMatchFilterGroup(buildEvent({ user_id: 'user-2', group_ids: ['group-a'] }), filterGroup)).toEqual(false);
    });

    it('falls back to <unknown> on missing user_id (so equality with a user filter fails)', () => {
      const filterGroup = {
        mode: 'and',
        filters: [{ key: ['members_user'], mode: 'or', operator: 'eq', values: ['user-1'] }],
        filterGroups: [],
      } as unknown as FilterGroup;
      expect(isOriginMatchFilterGroup(buildEvent({}), filterGroup)).toEqual(false);
      expect(isOriginMatchFilterGroup(buildEvent(undefined), filterGroup)).toEqual(false);
    });
  });

  describe('validateFilterGroupForStreamOriginMatch', () => {
    it('accepts a filter group containing only allowed origin keys', () => {
      const filterGroup = {
        mode: 'and',
        filters: [
          { key: ['members_user'], mode: 'or', operator: 'eq', values: ['user-1'] },
          { key: ['members_group'], mode: 'or', operator: 'eq', values: ['group-a'] },
          { key: ['members_organization'], mode: 'or', operator: 'eq', values: ['org-1'] },
        ],
        filterGroups: [],
      } as unknown as FilterGroup;
      expect(() => validateFilterGroupForStreamOriginMatch(filterGroup)).not.toThrow();
    });

    it('throws when a filter key is not allowed for origin filtering', () => {
      const filterGroup = {
        mode: 'and',
        filters: [{ key: ['entity_type'], mode: 'or', operator: 'eq', values: ['Report'] }],
        filterGroups: [],
      } as unknown as FilterGroup;
      expect(() => validateFilterGroupForStreamOriginMatch(filterGroup)).toThrow(/origin filtering is not compatible/);
    });

    it('throws when a filter has more than one key', () => {
      const filterGroup = {
        mode: 'and',
        filters: [{ key: ['members_user', 'members_group'], mode: 'or', operator: 'eq', values: ['x'] }],
        filterGroups: [],
      } as unknown as FilterGroup;
      expect(() => validateFilterGroupForStreamOriginMatch(filterGroup)).toThrow(/unique filter key/);
    });

    it('recursively validates nested filter groups', () => {
      const filterGroup = {
        mode: 'or',
        filters: [],
        filterGroups: [
          {
            mode: 'and',
            filters: [{ key: ['contextEntityId'], mode: 'or', operator: 'eq', values: ['x'] }],
            filterGroups: [],
          },
        ],
      } as unknown as FilterGroup;
      expect(() => validateFilterGroupForStreamOriginMatch(filterGroup)).toThrow(/origin filtering is not compatible/);
    });
  });
});
