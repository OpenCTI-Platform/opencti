import { describe, it, expect, vi } from 'vitest';
import { renderHook } from '@testing-library/react';
import useBuildSavedFiltersOptions from './useBuildSavedFiltersOptions';

vi.mock('src/utils/hooks/useAuth', () => ({
  default: () => ({
    me: { id: 'user-1' },
  }),
}));

describe('useBuildSavedFiltersOptions', () => {
  const makeItem = (overrides = {}) => ({
    id: 'filter-1',
    name: 'My Filter',
    creator_id: 'user-1',
    currentUserAccessRight: 'admin',
    authorizedMembers: [],
    ...overrides,
  });

  it('returns an empty array when data is empty', () => {
    const { result } = renderHook(() => useBuildSavedFiltersOptions([]));
    expect(result.current).toEqual([]);
  });

  it('builds options with correct label and value', () => {
    const item = makeItem();
    const { result } = renderHook(() => useBuildSavedFiltersOptions([item]));

    expect(result.current).toHaveLength(1);
    expect(result.current[0].label).toBe('My Filter');
    expect(result.current[0].value).toBe(item);
  });

  it('marks option as owner when creator_id matches current user', () => {
    const item = makeItem({ creator_id: 'user-1' });
    const { result } = renderHook(() => useBuildSavedFiltersOptions([item]));

    expect(result.current[0].isOwner).toBe(true);
    expect(result.current[0].ownerName).toBeUndefined();
  });

  it('marks option as not owner and includes ownerName when creator_id differs', () => {
    const item = makeItem({
      creator_id: 'user-2',
      authorizedMembers: [
        { member_id: 'user-2', name: 'Alice', id: 'member-1', entity_type: 'User', access_right: 'view' },
      ],
    });
    const { result } = renderHook(() => useBuildSavedFiltersOptions([item]));

    expect(result.current[0].isOwner).toBe(false);
    expect(result.current[0].ownerName).toBe('Alice');
  });

  it('sets ownerName to empty string when creator is not found in authorizedMembers', () => {
    const item = makeItem({
      creator_id: 'user-2',
      authorizedMembers: [],
    });
    const { result } = renderHook(() => useBuildSavedFiltersOptions([item]));

    expect(result.current[0].isOwner).toBe(false);
    expect(result.current[0].ownerName).toBe('');
  });

  it('sets canManage to true when currentUserAccessRight is admin', () => {
    const item = makeItem({ currentUserAccessRight: 'admin' });
    const { result } = renderHook(() => useBuildSavedFiltersOptions([item]));

    expect(result.current[0].canManage).toBe(true);
  });

  it('sets canManage to false when currentUserAccessRight is not admin', () => {
    const item = makeItem({ currentUserAccessRight: 'view' });
    const { result } = renderHook(() => useBuildSavedFiltersOptions([item]));

    expect(result.current[0].canManage).toBe(false);
  });

  it('sorts owned filters before shared filters', () => {
    const ownedItem = makeItem({ id: 'f1', name: 'Zebra', creator_id: 'user-1' });
    const sharedItem = makeItem({ id: 'f2', name: 'Alpha', creator_id: 'user-2' });
    const { result } = renderHook(() => useBuildSavedFiltersOptions([sharedItem, ownedItem]));

    expect(result.current[0].label).toBe('Zebra');
    expect(result.current[0].isOwner).toBe(true);
    expect(result.current[1].label).toBe('Alpha');
    expect(result.current[1].isOwner).toBe(false);
  });

  it('sorts alphabetically within the same ownership group', () => {
    const itemB = makeItem({ id: 'f1', name: 'Beta', creator_id: 'user-1' });
    const itemA = makeItem({ id: 'f2', name: 'Alpha', creator_id: 'user-1' });
    const itemC = makeItem({ id: 'f3', name: 'Charlie', creator_id: 'user-1' });
    const { result } = renderHook(() => useBuildSavedFiltersOptions([itemB, itemC, itemA]));

    expect(result.current.map((o) => o.label)).toEqual(['Alpha', 'Beta', 'Charlie']);
  });

  it('does not mutate the input data array', () => {
    const items = [
      makeItem({ id: 'f1', name: 'B', creator_id: 'user-1' }),
      makeItem({ id: 'f2', name: 'A', creator_id: 'user-1' }),
    ];
    const originalOrder = [...items];
    renderHook(() => useBuildSavedFiltersOptions(items));

    expect(items).toEqual(originalOrder);
  });
});
