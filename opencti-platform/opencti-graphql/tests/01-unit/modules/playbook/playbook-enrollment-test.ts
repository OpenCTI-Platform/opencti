import { describe, expect, it } from 'vitest';
import type { BasicStoreEntityPlaybook } from '../../../../src/modules/playbook/playbook-types';
import type { FilterGroup } from '../../../../src/generated/graphql';
import { STIX_EXT_OCTI } from '../../../../src/types/stix-2-1-extensions';
import type { StixObject as Stix21Object } from '../../../../src/types/stix-2-1-common';
import {
  allEntitiesMatchFilters,
  excludeEntitiesByIds,
  getEnrollmentEligibility,
  matchPlaybooksToEntities,
  type StixEntity,
  type StixFilterMatchFn,
} from '../../../../src/modules/playbook/playbook-enrollment';
import { emptyFilterGroup } from '../../../../src/utils/filtering/filtering-utils';

const buildPlaybook = (
  componentId: string,
  configuration: object,
  playbookStart = 'node-1',
): BasicStoreEntityPlaybook => ({
  playbook_start: playbookStart,
  playbook_definition: JSON.stringify({
    nodes: [{
      id: playbookStart,
      component_id: componentId,
      configuration: JSON.stringify(configuration),
    }],
  }),
} as unknown as BasicStoreEntityPlaybook);

const buildPlaybookWithFilters = (filters: FilterGroup): BasicStoreEntityPlaybook => buildPlaybook(
  'PLAYBOOK_INTERNAL_DATA_STREAM',
  { canEnrollManually: true, filters: JSON.stringify(filters) },
);

const fakeEntity = (id: string): StixEntity => ({ id, type: 'malware', spec_version: '2.1' }) as unknown as StixEntity;

const fakeStixEntityWithInternalId = (internalId: string): Stix21Object => ({
  id: `malware--${internalId}`,
  type: 'malware',
  spec_version: '2.1',
  extensions: { [STIX_EXT_OCTI]: { id: internalId } },
} as unknown as Stix21Object);

describe('getEnrollmentEligibility', () => {
  it('returns null when playbook_definition is missing', () => {
    const playbook = { playbook_start: 'x', playbook_definition: null } as unknown as BasicStoreEntityPlaybook;
    expect(getEnrollmentEligibility(playbook)).toBeNull();
  });

  it('returns null when start node is not found in definition', () => {
    const playbook = {
      playbook_start: 'missing-node',
      playbook_definition: JSON.stringify({ nodes: [{ id: 'other', component_id: 'X', configuration: '{}' }] }),
    } as unknown as BasicStoreEntityPlaybook;
    expect(getEnrollmentEligibility(playbook)).toBeNull();
  });

  it('returns null when component_id is not a valid manual trigger', () => {
    const playbook = buildPlaybook('PLAYBOOK_SOME_OTHER', { canEnrollManually: true });
    expect(getEnrollmentEligibility(playbook)).toBeNull();
  });

  it('returns null when canEnrollManually is false', () => {
    const playbook = buildPlaybook('PLAYBOOK_INTERNAL_DATA_STREAM', { canEnrollManually: false });
    expect(getEnrollmentEligibility(playbook)).toBeNull();
  });

  it('returns eligible with null filters when no filters configured', () => {
    const playbook = buildPlaybook('PLAYBOOK_INTERNAL_DATA_STREAM', { canEnrollManually: true });
    const result = getEnrollmentEligibility(playbook);
    expect(result).not.toBeNull();
    expect(result!.playbook).toBe(playbook);
    expect(result!.jsonFilters).toBeNull();
  });

  it('returns eligible with parsed filters', () => {
    const playbook = buildPlaybookWithFilters(emptyFilterGroup);
    const result = getEnrollmentEligibility(playbook);
    expect(result).not.toBeNull();
    expect(result!.jsonFilters).toEqual(emptyFilterGroup);
  });

  it('treats canEnrollManually as true when undefined', () => {
    const playbook = buildPlaybook('PLAYBOOK_INTERNAL_MANUAL_TRIGGER', {});
    const result = getEnrollmentEligibility(playbook);
    expect(result).not.toBeNull();
  });

  it('accepts PLAYBOOK_INTERNAL_DATA_STREAM', () => {
    const playbook = buildPlaybook('PLAYBOOK_INTERNAL_DATA_STREAM', {});
    expect(getEnrollmentEligibility(playbook)).not.toBeNull();
  });

  it('accepts PLAYBOOK_INTERNAL_MANUAL_TRIGGER', () => {
    const playbook = buildPlaybook('PLAYBOOK_INTERNAL_MANUAL_TRIGGER', {});
    expect(getEnrollmentEligibility(playbook)).not.toBeNull();
  });
});

describe('allEntitiesMatchFilters', () => {
  const alwaysMatch: StixFilterMatchFn = async () => true;
  const neverMatch: StixFilterMatchFn = async () => false;

  it('returns true when all entities match', async () => {
    const entities = [fakeEntity('a'), fakeEntity('b')];
    const result = await allEntitiesMatchFilters(entities, emptyFilterGroup, alwaysMatch);
    expect(result).toBe(true);
  });

  it('returns false when any entity does not match', async () => {
    let callCount = 0;
    const matchSecondFails: StixFilterMatchFn = async () => {
      callCount += 1;
      return callCount !== 2;
    };
    const entities = [fakeEntity('a'), fakeEntity('b'), fakeEntity('c')];
    const result = await allEntitiesMatchFilters(entities, emptyFilterGroup, matchSecondFails);
    expect(result).toBe(false);
  });

  it('short-circuits on first non-match', async () => {
    let callCount = 0;
    const matchFn: StixFilterMatchFn = async () => {
      callCount += 1;
      return false;
    };
    const entities = [fakeEntity('a'), fakeEntity('b'), fakeEntity('c')];
    await allEntitiesMatchFilters(entities, emptyFilterGroup, matchFn);
    expect(callCount).toBe(1);
  });

  it('returns true for empty entity list', async () => {
    const result = await allEntitiesMatchFilters([], emptyFilterGroup, neverMatch);
    expect(result).toBe(true);
  });
});

describe('matchPlaybooksToEntities', () => {
  const alwaysMatch: StixFilterMatchFn = async () => true;
  const neverMatch: StixFilterMatchFn = async () => false;

  it('includes playbooks with null filters unconditionally', async () => {
    const playbook = buildPlaybook('PLAYBOOK_INTERNAL_DATA_STREAM', {});
    const eligible = [{ playbook, jsonFilters: null }];
    const result = await matchPlaybooksToEntities(eligible, [fakeEntity('x')], neverMatch);
    expect(result).toEqual([playbook]);
  });

  it('includes playbooks when all entities match filters', async () => {
    const playbook = buildPlaybookWithFilters(emptyFilterGroup);
    const eligible = [{ playbook, jsonFilters: emptyFilterGroup }];
    const result = await matchPlaybooksToEntities(eligible, [fakeEntity('x')], alwaysMatch);
    expect(result).toEqual([playbook]);
  });

  it('excludes playbooks when any entity does not match', async () => {
    const playbook = buildPlaybookWithFilters(emptyFilterGroup);
    const eligible = [{ playbook, jsonFilters: emptyFilterGroup }];
    const result = await matchPlaybooksToEntities(eligible, [fakeEntity('x')], neverMatch);
    expect(result).toEqual([]);
  });

  it('handles mixed eligible playbooks correctly', async () => {
    const noFilterPlaybook = buildPlaybook('PLAYBOOK_INTERNAL_DATA_STREAM', {});
    const withFilterPlaybook = buildPlaybookWithFilters(emptyFilterGroup);
    const eligible = [
      { playbook: noFilterPlaybook, jsonFilters: null },
      { playbook: withFilterPlaybook, jsonFilters: emptyFilterGroup },
    ];
    const result = await matchPlaybooksToEntities(eligible, [fakeEntity('x')], neverMatch);
    expect(result).toEqual([noFilterPlaybook]);
  });

  it('returns empty array when no playbooks are eligible', async () => {
    const result = await matchPlaybooksToEntities([], [fakeEntity('x')], alwaysMatch);
    expect(result).toEqual([]);
  });
});

describe('excludeEntitiesByIds', () => {
  it('returns all entities when excludedIds is empty', () => {
    const entities = [fakeStixEntityWithInternalId('internal-a')];
    expect(excludeEntitiesByIds(entities, [])).toEqual(entities);
  });

  it('removes entities whose internal id is in excludedIds', () => {
    const keep = fakeStixEntityWithInternalId('internal-a');
    const remove = fakeStixEntityWithInternalId('internal-b');
    const result = excludeEntitiesByIds([keep, remove], ['internal-b']);
    expect(result).toEqual([keep]);
  });

  it('keeps entities when none match the excluded ids', () => {
    const firstEntity = fakeStixEntityWithInternalId('internal-a');
    const secondEntity = fakeStixEntityWithInternalId('internal-b');
    const result = excludeEntitiesByIds([firstEntity, secondEntity], ['internal-c']);
    expect(result).toEqual([firstEntity, secondEntity]);
  });

  it('keeps entities whose extension id is undefined', () => {
    const entity = {
      id: 'malware--x',
      type: 'malware',
      spec_version: '2.1',
      extensions: { [STIX_EXT_OCTI]: {} },
    } as unknown as Stix21Object;
    const result = excludeEntitiesByIds([entity], ['some-id']);
    expect(result).toEqual([entity]);
  });

  it('removes all entities when all are excluded', () => {
    const firstEntity = fakeStixEntityWithInternalId('internal-a');
    const secondEntity = fakeStixEntityWithInternalId('internal-b');
    const result = excludeEntitiesByIds([firstEntity, secondEntity], ['internal-a', 'internal-b']);
    expect(result).toEqual([]);
  });
});
