import { describe, it, expect } from 'vitest';
import { FilterMode } from '../../../src/generated/graphql';
import { isPirExplanationsNotInMetaRel } from '../../../src/modules/pir/pir-utils';

describe('Pir utilities: isExplanationsAlreadyInPirMetaRels', () => {
  it('should return true if', () => {
    const relationshipId1 = '95ee60cf-8aa8-4cd5-8c7d-11e76798d04e';
    const relationshipId2 = '69e78b70-97c5-4db0-859d-2221f8e87fe9';
    const filters1 = {
      mode: FilterMode.And,
      filterGroups: [],
      filters: [
        { key: ['toId'], values: ['24b6365f-dd85-4ee3-a28d-bb4b37e1619c'] }
      ]
    };
    const filters2 = {
      mode: FilterMode.And,
      filterGroups: [],
      filters: [
        { key: ['toId'], values: ['d17360d5-0b58-4a21-bebc-84aa5a3f32b4'] }
      ]
    };
    const pirMetaRelExplanations = [
      {
        criterion: {
          weight: 2,
          filters: JSON.stringify(filters1),
        },
        dependency_ids: [relationshipId1]
      },
      {
        criterion: {
          weight: 1,
          filters: JSON.stringify(filters2),
        },
        dependency_ids: [relationshipId2]
      }
    ];
    expect(isPirExplanationsNotInMetaRel(pirMetaRelExplanations, [
      {
        dependency_ids: [relationshipId1],
        criterion: {
          weight: 2,
          filters: JSON.stringify(filters1),
        },
      }
    ])).toEqual(true);
    expect(isPirExplanationsNotInMetaRel(pirMetaRelExplanations, [
      {
        dependency_ids: [relationshipId2],
        criterion: {
          weight: 2,
          filters: JSON.stringify(filters1),
        },
      }
    ])).toEqual(false);
    expect(isPirExplanationsNotInMetaRel(pirMetaRelExplanations, [
      {
        dependency_ids: [relationshipId1],
        criterion: {
          weight: 2,
          filters: JSON.stringify(filters2),
        },
      }
    ])).toEqual(false);
    expect(isPirExplanationsNotInMetaRel(pirMetaRelExplanations, [
      {
        dependency_ids: [relationshipId1, relationshipId2],
        criterion: {
          weight: 1,
          filters: JSON.stringify(filters1),
        },
      }
    ])).toEqual(false);
  }); // TODO PIR case of several dep in the second argument
});
