import { describe, it, expect } from 'vitest';
import { FilterMode } from '../../../src/generated/graphql';
import { arePirExplanationsEqual, diffPirExplanations } from '../../../src/modules/pir/pir-utils';

const createFilter = (id: string) => {
  return JSON.stringify({
    mode: FilterMode.And,
    filterGroups: [],
    filters: [{ key: ['toId'], values: [id] }]
  });
};

const relationshipId1 = '95ee60cf-8aa8-4cd5-8c7d-11e76798d04e';
const relationshipId2 = '69e78b70-97c5-4db0-859d-2221f8e87fe9';
const relationshipId3 = 'ab143b66-5c8c-4584-b378-a00e03fccd8c';
const relationshipId4 = '69e78b70-97c5-4db0-859d-2221f8e87fe9';
const filters1 = createFilter('24b6365f-dd85-4ee3-a28d-bb4b37e1619c');
const filters2 = createFilter('d17360d5-0b58-4a21-bebc-84aa5a3f32b4');
const filters3 = createFilter('527e5e30-02c5-4ba9-a698-45954d1f3763');
const filters4 = createFilter('bafe1462-a53e-4b60-9c24-cdfb4f1bfe18');

describe('Pir utilities: arePirExplanationsEqual()', () => {
  it('should return false if not the same weights', () => {
    expect(arePirExplanationsEqual(
      {
        dependency_ids: [relationshipId1],
        criterion: { weight: 1, filters: filters1 }
      },
      {
        dependency_ids: [relationshipId1],
        criterion: { weight: 2, filters: filters1 }
      }
    )).toEqual(false);
  });

  it('should return false if not the same filters', () => {
    expect(arePirExplanationsEqual(
      {
        dependency_ids: [relationshipId1],
        criterion: { weight: 1, filters: filters1 }
      },
      {
        dependency_ids: [relationshipId1],
        criterion: { weight: 1, filters: filters2 }
      }
    )).toEqual(false);
  });

  it('should return false if not the same array of dependencies', () => {
    expect(arePirExplanationsEqual(
      {
        dependency_ids: [relationshipId1],
        criterion: { weight: 1, filters: filters1 }
      },
      {
        dependency_ids: [relationshipId2],
        criterion: { weight: 1, filters: filters1 }
      }
    )).toEqual(false);
  });

  it('should return true if same explanation', () => {
    expect(arePirExplanationsEqual(
      {
        dependency_ids: [relationshipId1, relationshipId2],
        criterion: { weight: 1, filters: filters1 }
      },
      {
        dependency_ids: [relationshipId1, relationshipId2],
        criterion: { weight: 1, filters: filters1 }
      }
    )).toEqual(true);
  });
});

describe('Pir utilities: diffPirExplanations()', () => {
  const baseExplanations = [
    {
      dependency_ids: [relationshipId1, relationshipId1],
      criterion: { weight: 1, filters: filters1 }
    },
    {
      dependency_ids: [relationshipId2, relationshipId2],
      criterion: { weight: 1, filters: filters2 }
    }
  ];

  it('should return an empty array if given an empty array', () => {
    expect(diffPirExplanations([], baseExplanations)).toEqual([]);
  });

  it('should return an empty array if all the same', () => {
    expect(diffPirExplanations(baseExplanations, baseExplanations)).toEqual([]);
  });

  it('should return same array if base is empty', () => {
    expect(diffPirExplanations([
      {
        dependency_ids: [relationshipId1, relationshipId1],
        criterion: { weight: 1, filters: filters1 }
      },
      {
        dependency_ids: [relationshipId2, relationshipId2],
        criterion: { weight: 1, filters: filters2 }
      }
    ], [])).toEqual([
      {
        dependency_ids: [relationshipId1, relationshipId1],
        criterion: { weight: 1, filters: filters1 }
      },
      {
        dependency_ids: [relationshipId2, relationshipId2],
        criterion: { weight: 1, filters: filters2 }
      }
    ]);
  });

  it('should return same array if all different from base', () => {
    expect(diffPirExplanations([
      {
        dependency_ids: [relationshipId3, relationshipId3],
        criterion: { weight: 1, filters: filters3 }
      },
      {
        dependency_ids: [relationshipId4, relationshipId4],
        criterion: { weight: 1, filters: filters4 }
      }
    ], baseExplanations)).toEqual([
      {
        dependency_ids: [relationshipId3, relationshipId3],
        criterion: { weight: 1, filters: filters3 }
      },
      {
        dependency_ids: [relationshipId4, relationshipId4],
        criterion: { weight: 1, filters: filters4 }
      }
    ]);
  });

  it('should return diff array if some are different', () => {
    expect(diffPirExplanations([
      {
        dependency_ids: [relationshipId2, relationshipId2],
        criterion: { weight: 1, filters: filters2 }
      },
      {
        dependency_ids: [relationshipId4, relationshipId4],
        criterion: { weight: 1, filters: filters4 }
      }
    ], baseExplanations)).toEqual([
      {
        dependency_ids: [relationshipId4, relationshipId4],
        criterion: { weight: 1, filters: filters4 }
      }
    ]);
  });
});
