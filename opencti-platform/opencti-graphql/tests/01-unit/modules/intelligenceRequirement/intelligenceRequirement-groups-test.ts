import { beforeEach, describe, expect, it, vi } from 'vitest';
import * as middlewareLoader from '../../../../src/database/middleware-loader';
import { groupMemberIds, groupMemberSet, resetSubjectGroupCache, resolveSubjectGroup } from '../../../../src/modules/intelligenceRequirement/intelligenceRequirement-groups';
import type { ParsedIntelligenceRequirement, StoreIrSubjectGroup } from '../../../../src/modules/intelligenceRequirement/intelligenceRequirement-types';
import type { BasicStoreEntity } from '../../../../src/types/store';
import { ADMIN_USER, testContext } from '../../../utils/testQuery';

const entity = (id: string) => ({ internal_id: id, standard_id: `malware--${id}` }) as unknown as BasicStoreEntity;

const group = (id: string, kind: string, extra: Partial<StoreIrSubjectGroup> = {}): StoreIrSubjectGroup => ({
  id,
  name: id,
  kind,
  role: 'entry',
  entity_ids: [],
  filters: null,
  keywords: [],
  ...extra,
});

const ransomwareFilter = JSON.stringify({ mode: 'and', filterGroups: [], filters: [{ key: ['entity_type'], values: ['Malware'] }] });

const requirement = (groups: StoreIrSubjectGroup[]) => ({ ir_subject_groups: groups }) as unknown as ParsedIntelligenceRequirement;

describe('Intelligence requirement subject groups', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    resetSubjectGroupCache();
  });

  it('should resolve a list group to its entities and keep the listed ids', async () => {
    const findByIds = vi.spyOn(middlewareLoader, 'internalFindByIds').mockResolvedValue([entity('a')] as never);
    const members = await resolveSubjectGroup(testContext, ADMIN_USER, group('g1', 'list', { entity_ids: ['a', 'missing'] }));
    expect(findByIds).toHaveBeenCalledTimes(1);
    expect(members.internalIds).toEqual(['a']);
    expect(Array.from(members.allIds).sort()).toEqual(['a', 'malware--a', 'missing']);
  });

  it('should resolve a filter group with its dynamic filter and cache the result', async () => {
    const list = vi.spyOn(middlewareLoader, 'fullEntitiesList').mockResolvedValue([entity('r1'), entity('r2')] as never);
    const filterGroup = group('g2', 'filter', { filters: ransomwareFilter });
    const first = await resolveSubjectGroup(testContext, ADMIN_USER, filterGroup);
    const second = await resolveSubjectGroup(testContext, ADMIN_USER, filterGroup);
    expect(list).toHaveBeenCalledTimes(1);
    expect(second).toBe(first);
    expect(first.internalIds).toEqual(['r1', 'r2']);
    resetSubjectGroupCache();
    await resolveSubjectGroup(testContext, ADMIN_USER, filterGroup);
    expect(list).toHaveBeenCalledTimes(2);
  });

  it('should resolve an empty list group or an unreadable filter to no member', async () => {
    const findByIds = vi.spyOn(middlewareLoader, 'internalFindByIds').mockResolvedValue([] as never);
    const list = vi.spyOn(middlewareLoader, 'fullEntitiesList').mockResolvedValue([] as never);
    const empty = await resolveSubjectGroup(testContext, ADMIN_USER, group('g3', 'list'));
    const broken = await resolveSubjectGroup(testContext, ADMIN_USER, group('g4', 'filter', { filters: '{not json' }));
    expect(findByIds).not.toHaveBeenCalled();
    expect(list).not.toHaveBeenCalled();
    expect(empty.internalIds).toEqual([]);
    expect(broken.allIds.size).toEqual(0);
  });

  it('should union the members of several groups and ignore keywords groups', async () => {
    vi.spyOn(middlewareLoader, 'internalFindByIds').mockResolvedValue([entity('a')] as never);
    vi.spyOn(middlewareLoader, 'fullEntitiesList').mockResolvedValue([entity('a'), entity('b')] as never);
    const ir = requirement([
      group('list', 'list', { entity_ids: ['a'] }),
      group('filter', 'filter', { filters: ransomwareFilter }),
      group('words', 'keywords', { keywords: ['fortios'] }),
    ]);
    const set = await groupMemberSet(testContext, ADMIN_USER, ir, ['list', 'filter', 'words']);
    expect(Array.from(set).sort()).toEqual(['a', 'b', 'malware--a', 'malware--b']);
    const single = await groupMemberSet(testContext, ADMIN_USER, ir, ['list']);
    expect(Array.from(single).sort()).toEqual(['a', 'malware--a']);
    const ids = await groupMemberIds(testContext, ADMIN_USER, ir, ['list', 'filter', 'words']);
    expect(ids.sort()).toEqual(['a', 'b']);
    expect(await groupMemberIds(testContext, ADMIN_USER, ir, ['words'])).toEqual([]);
  });
});
