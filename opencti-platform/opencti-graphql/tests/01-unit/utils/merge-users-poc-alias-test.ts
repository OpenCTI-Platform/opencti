import { afterEach, describe, expect, it } from 'vitest';
import {
  canonicalizeMergeUsersPocAliasIds,
  canonicalizeMergeUsersPocAliasUpdateInputs,
  coalesceMergeUsersPocAliasAggregationBuckets,
  expandMergeUsersPocAliasFilterGroup,
  expandMergeUsersPocAliasIds,
  getMergeUsersPocCanonicalAliasMap,
  resolveMergeUsersPocAliasId,
} from '../../../src/utils/merge-users-poc-alias';
import { type Filter, type FilterGroup, FilterMode, FilterOperator } from '../../../src/generated/graphql';
import { testAssignee, testCreatedBy, testCreator, testParticipant } from '../../../src/utils/filtering/filtering-stix/stix-testers';
import { STIX_EXT_OCTI } from '../../../src/types/stix-2-1-extensions';
import { getExplicitUserAccessRight, MEMBER_ACCESS_RIGHT_VIEW, SYSTEM_USER } from '../../../src/utils/access';

const SOURCE_ID = '11111111-1111-4111-8111-111111111111';
const INTERMEDIATE_ID = '22222222-2222-4222-8222-222222222222';
const TARGET_ID = '33333333-3333-4333-8333-333333333333';

const enableAlias = (aliases: Record<string, string> = { [SOURCE_ID]: TARGET_ID }) => {
  process.env.MERGE_POC_ALIAS_MAP = JSON.stringify(aliases);
};

afterEach(() => {
  delete process.env.MERGE_POC_ALIAS_MAP;
});

describe('Merge users PoC alias policies', () => {
  it('is a no-op unless explicitly enabled', () => {
    expect(resolveMergeUsersPocAliasId(SOURCE_ID)).toEqual(SOURCE_ID);
    expect(expandMergeUsersPocAliasIds([TARGET_ID])).toEqual([TARGET_ID]);
  });

  it('rejects malformed maps and alias cycles instead of silently changing behavior', () => {
    process.env.MERGE_POC_ALIAS_MAP = 'not-json';
    expect(() => resolveMergeUsersPocAliasId(SOURCE_ID)).toThrow('MERGE_POC_ALIAS_MAP must be a JSON object');

    enableAlias({ [SOURCE_ID]: 'User--33333333-3333-4333-8333-333333333333' });
    expect(() => resolveMergeUsersPocAliasId(SOURCE_ID)).toThrow('MERGE_POC_ALIAS_MAP entries must contain internal user ids');

    enableAlias({ [SOURCE_ID]: INTERMEDIATE_ID, [INTERMEDIATE_ID]: SOURCE_ID });
    expect(() => resolveMergeUsersPocAliasId(SOURCE_ID)).toThrow('MERGE_POC_ALIAS_MAP contains a cycle');
  });

  it('canonicalizes writes and expands reads across transitive aliases', () => {
    enableAlias({ [SOURCE_ID]: INTERMEDIATE_ID, [INTERMEDIATE_ID]: TARGET_ID });

    expect(resolveMergeUsersPocAliasId(SOURCE_ID)).toEqual(TARGET_ID);
    expect(canonicalizeMergeUsersPocAliasIds([SOURCE_ID, INTERMEDIATE_ID, TARGET_ID])).toEqual([TARGET_ID]);
    expect(expandMergeUsersPocAliasIds([TARGET_ID])).toEqual([TARGET_ID, SOURCE_ID, INTERMEDIATE_ID]);
    expect(getMergeUsersPocCanonicalAliasMap()).toEqual({
      [SOURCE_ID]: TARGET_ID,
      [INTERMEDIATE_ID]: TARGET_ID,
    });
  });

  it('expands only operational user filters, including nested groups', () => {
    enableAlias();
    const filters: FilterGroup = {
      mode: FilterMode.And,
      filters: [
        { key: ['creator_id'], values: [TARGET_ID], operator: FilterOperator.Eq },
        { key: ['restricted_members'], values: [TARGET_ID], operator: FilterOperator.Eq },
        { key: ['createdBy'], values: [TARGET_ID], operator: FilterOperator.Eq },
      ],
      filterGroups: [{
        mode: FilterMode.Or,
        filters: [{ key: ['objectAssignee'], values: [TARGET_ID], operator: FilterOperator.Eq }],
        filterGroups: [],
      }],
    };

    const expanded = expandMergeUsersPocAliasFilterGroup(filters);

    expect(expanded.filters[0].values).toEqual([TARGET_ID, SOURCE_ID]);
    expect(expanded.filters[1].values).toEqual([TARGET_ID]);
    expect(expanded.filters[2].values).toEqual([TARGET_ID]);
    expect(expanded.filterGroups[0].filters[0].values).toEqual([TARGET_ID, SOURCE_ID]);
    expect(filters.filters[0].values).toEqual([TARGET_ID]);
  });

  it('supports legacy string filter keys', () => {
    enableAlias();
    const filters: FilterGroup = {
      mode: FilterMode.And,
      filters: [{
        key: 'creator_id',
        values: [TARGET_ID],
      } as unknown as Filter],
      filterGroups: [],
    };

    expect(expandMergeUsersPocAliasFilterGroup(filters).filters[0].values).toEqual([TARGET_ID, SOURCE_ID]);
  });

  it('canonicalizes generic operational updates and expands removals', () => {
    enableAlias();

    expect(canonicalizeMergeUsersPocAliasUpdateInputs([
      { key: 'creator_id', value: [SOURCE_ID], operation: 'replace' },
      { key: 'objectAssignee', value: [SOURCE_ID], operation: 'add' },
      { key: 'objectParticipant', value: [TARGET_ID], operation: 'remove' },
      { key: 'restricted_members', value: [SOURCE_ID], operation: 'replace' },
    ])).toEqual([
      { key: 'creator_id', value: [TARGET_ID], operation: 'replace' },
      { key: 'objectAssignee', value: [TARGET_ID], operation: 'add' },
      { key: 'objectParticipant', value: [TARGET_ID, SOURCE_ID], operation: 'remove' },
      { key: 'restricted_members', value: [SOURCE_ID], operation: 'replace' },
    ]);
  });

  it('coalesces source and target aggregation buckets without double listing the user', () => {
    enableAlias();

    expect(coalesceMergeUsersPocAliasAggregationBuckets([
      { key: SOURCE_ID, doc_count: 2 },
      { key: TARGET_ID, doc_count: 3 },
      { key: 'other-user', doc_count: 1 },
    ])).toEqual([
      { key: TARGET_ID, doc_count: 5 },
      { key: 'other-user', doc_count: 1 },
    ]);
  });

  it('matches operational stream filters by alias while preserving historical attribution', () => {
    enableAlias();
    const stix = {
      created_by_ref: SOURCE_ID,
      extensions: {
        [STIX_EXT_OCTI]: {
          creator_ids: [SOURCE_ID],
          assignee_ids: [SOURCE_ID],
          participant_ids: [SOURCE_ID],
        },
      },
    };
    const filter: Filter = {
      key: ['creator'],
      mode: FilterMode.Or,
      operator: FilterOperator.Eq,
      values: [TARGET_ID],
    };

    expect(testCreator(stix, filter)).toBe(true);
    expect(testAssignee(stix, { ...filter, key: ['objectAssignee'] })).toBe(true);
    expect(testParticipant(stix, { ...filter, key: ['objectParticipant'] })).toBe(true);
    expect(testCreatedBy(stix, { ...filter, key: ['createdBy'] })).toBe(false);
  });

  it('does not inherit restricted-member access from the source user', () => {
    enableAlias();
    const user = (id: string) => ({
      ...SYSTEM_USER,
      id,
      internal_id: id,
      capabilities: [],
      organizations: [],
      roles: [],
      groups: [],
    });
    const element = {
      restricted_members: [{
        id: SOURCE_ID,
        access_right: MEMBER_ACCESS_RIGHT_VIEW,
        groups_restriction_ids: [],
      }],
      authorized_authorities: [],
    };

    expect(getExplicitUserAccessRight(user(SOURCE_ID), element)).toEqual(MEMBER_ACCESS_RIGHT_VIEW);
    expect(getExplicitUserAccessRight(user(TARGET_ID), element)).toBeNull();
  });
});
