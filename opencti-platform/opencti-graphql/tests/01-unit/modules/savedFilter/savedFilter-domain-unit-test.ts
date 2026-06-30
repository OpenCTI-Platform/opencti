import { describe, expect, it } from 'vitest';
import { isSavedFilterShared } from '../../../../src/modules/savedFilter/savedFilter-domain';
import type { BasicStoreEntitySavedFilter } from '../../../../src/modules/savedFilter/savedFilter-types';

const buildSavedFilter = (creatorId: string, restrictedMembers: { id: string; access_right: string }[] | undefined): BasicStoreEntitySavedFilter => {
  return {
    creator_id: creatorId,
    restricted_members: restrictedMembers,
  } as unknown as BasicStoreEntitySavedFilter;
};

describe('isSavedFilterShared', () => {
  it('should return false when restricted_members is undefined', () => {
    const filter = buildSavedFilter('user-1', undefined);
    expect(isSavedFilterShared(filter)).toBe(false);
  });

  it('should return false when restricted_members is empty', () => {
    const filter = buildSavedFilter('user-1', []);
    expect(isSavedFilterShared(filter)).toBe(false);
  });

  it('should return false when restricted_members contains only the creator', () => {
    const filter = buildSavedFilter('user-1', [
      { id: 'user-1', access_right: 'admin' },
    ]);
    expect(isSavedFilterShared(filter)).toBe(false);
  });

  it('should return true when restricted_members contains another member', () => {
    const filter = buildSavedFilter('user-1', [
      { id: 'user-1', access_right: 'admin' },
      { id: 'user-2', access_right: 'view' },
    ]);
    expect(isSavedFilterShared(filter)).toBe(true);
  });

  it('should return true when restricted_members contains only other members (no creator)', () => {
    const filter = buildSavedFilter('user-1', [
      { id: 'user-2', access_right: 'admin' },
    ]);
    expect(isSavedFilterShared(filter)).toBe(true);
  });

  it('should return true when shared with MEMBER_ACCESS_ALL', () => {
    const filter = buildSavedFilter('user-1', [
      { id: 'user-1', access_right: 'admin' },
      { id: 'ALL', access_right: 'view' },
    ]);
    expect(isSavedFilterShared(filter)).toBe(true);
  });
});
