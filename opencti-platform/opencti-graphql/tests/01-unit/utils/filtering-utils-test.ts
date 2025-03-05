import { describe, expect, it } from 'vitest';
import { addFilter, checkFiltersValidity, convertRelationRefsFilterKeys, extractFilterGroupValues, replaceFilterKey } from '../../../src/utils/filtering/filtering-utils';
import type { FilterGroup } from '../../../src/generated/graphql';

describe('Filtering utils', () => {
  it('should check a filter syntax', async () => {
    const filterGroup1 = {
      mode: 'or',
      filters: [
        { key: [], values: ['Report'], operator: 'eq', mode: 'or' },
        { key: ['publication_date'], values: ['YYY'] },
      ],
      filterGroups: [],
    } as FilterGroup;
    expect(() => checkFiltersValidity(filterGroup1)).toThrowError('A filter key must be defined for every filter');
    const filterGroup2 = {
      mode: 'or',
      filters: [
        { key: ['publication_date'], values: ['YYY'] },
      ],
      filterGroups: [{
        mode: 'or',
        filters: [
          { key: [], values: ['marking1'], operator: 'eq', mode: 'or' },
          { key: ['objectLabel'], values: ['label1'], operator: 'eq', mode: 'or' },
        ],
        filterGroups: [],
      }],
    } as FilterGroup;
    expect(() => checkFiltersValidity(filterGroup2)).toThrowError('A filter key must be defined for every filter');
  });
  it('should check a filter syntax for filter with "within" operator', async () => {
    const filterGroup1 = {
      mode: 'or',
      filters: [
        { key: ['published'], values: ['now'], operator: 'within' },
      ],
      filterGroups: [],
    } as FilterGroup;
    expect(() => checkFiltersValidity(filterGroup1)).toThrowError('A filter with "within" operator must have 2 values');
    const filterGroup2 = {
      mode: 'or',
      filters: [
        { key: ['published'], values: ['now', ''], operator: 'within' },
      ],
      filterGroups: [],
    } as FilterGroup;
    expect(() => checkFiltersValidity(filterGroup2)).toThrowError('A filter with "within" operator must have 2 values');
    const filterGroup3 = {
      mode: 'or',
      filters: [
        { key: ['published'], values: ['now-1y', 'now3'], operator: 'within' },
      ],
      filterGroups: [],
    } as FilterGroup;
    expect(() => checkFiltersValidity(filterGroup3)).toThrowError('The values for filter with "within" operator are not valid: you should provide a datetime or a valid relative date.');
    const filterGroup4 = {
      mode: 'or',
      filters: [
        { key: ['published'], values: ['now-1y', 'now'], operator: 'within' },
      ],
      filterGroups: [],
    } as FilterGroup;
    expect(() => checkFiltersValidity(filterGroup4)).not.toThrowError();
    const filterGroup5 = {
      mode: 'or',
      filters: [
        { key: ['published'], values: ['now', '2039-09-T00:51:35.000Z'], operator: 'within' },
      ],
      filterGroups: [],
    } as FilterGroup;
    expect(() => checkFiltersValidity(filterGroup5)).toThrowError('The values for filter with "within" operator are not valid: you should provide a datetime or a valid relative date.');
    const filterGroup6 = {
      mode: 'or',
      filters: [
        { key: ['published'], values: ['2023-09-01T00:51:35.000Z', '2023-09-30T00:51:35.000Z'], operator: 'within' },
      ],
      filterGroups: [],
    } as FilterGroup;
    expect(() => checkFiltersValidity(filterGroup6)).not.toThrowError();
    const filterGroup7 = {
      mode: 'or',
      filters: [
        { key: ['published'], values: ['now-1d/d', 'now'], operator: 'within' },
      ],
      filterGroups: [],
    } as FilterGroup;
    expect(() => checkFiltersValidity(filterGroup7)).not.toThrowError();
    const filterGroup8 = {
      mode: 'or',
      filters: [
        { key: ['published'], values: ['now-1d/', 'now'], operator: 'within' },
      ],
      filterGroups: [],
    } as FilterGroup;
    expect(() => checkFiltersValidity(filterGroup8)).toThrowError();
    const filterGroup9 = {
      mode: 'or',
      filters: [
        { key: ['published'], values: ['10y/y', 'now'], operator: 'within' },
      ],
      filterGroups: [],
    } as FilterGroup;
    expect(() => checkFiltersValidity(filterGroup9)).toThrowError();
  });
  it('should add a filter to a filter group and separate them with the AND mode', async () => {
    const filterGroup = {
      mode: 'or',
      filters: [
        { key: ['entity_type'], values: ['Report'], operator: 'eq', mode: 'or' },
        { key: ['publication_date'], values: ['YYY'] },
      ],
      filterGroups: [],
    } as FilterGroup;
    const expectedFilter = {
      mode: 'and',
      filters: [{ key: ['objectLabel'], values: ['label1-id', 'label2-id'], operator: 'eq', mode: 'or' }],
      filterGroups: [filterGroup],
    };
    const newFilter = addFilter(filterGroup, 'objectLabel', ['label1-id', 'label2-id']);
    expect(newFilter).toEqual(expectedFilter);
  });
  it('should replace a filter key by another in a filter group', async () => {
    const filterGroup = {
      mode: 'or',
      filters: [
        { key: ['entity_type'], values: ['Report'], operator: 'eq', mode: 'or' },
        { key: ['oldKey'], values: ['YYY'] },
      ],
      filterGroups: [
        {
          mode: 'and',
          filters: [
            { key: ['newKey'], values: ['ZZZ'], operator: 'not_eq', mode: 'or' },
            { key: ['oldKey', 'name'], values: ['aaa'] },
            { key: ['value'], values: ['bbb'] },
          ],
          filterGroups: [],
        }
      ],
    } as FilterGroup;
    const expectedFilter = {
      mode: 'or',
      filters: [
        { key: ['entity_type'], values: ['Report'], operator: 'eq', mode: 'or' },
        { key: ['newKey'], values: ['YYY'] },
      ],
      filterGroups: [
        {
          mode: 'and',
          filters: [
            { key: ['newKey'], values: ['ZZZ'], operator: 'not_eq', mode: 'or' },
            { key: ['newKey', 'name'], values: ['aaa'] },
            { key: ['value'], values: ['bbb'] },
          ],
          filterGroups: [],
        }
      ],
    };
    const newFilter = replaceFilterKey(filterGroup, 'oldKey', 'newKey');
    expect(newFilter).toEqual(expectedFilter);
  });
  it('should convert special keys from frontend format to backend format in a filter group', async () => {
    const filterGroup = {
      mode: 'or',
      filters: [
        { key: ['related-to'], values: ['xxx'], operator: 'eq', mode: 'or' },
        { key: ['contextEntityId'], values: ['YYY'] },
        { key: ['members_user'], values: ['ZZZ'] },
      ],
      filterGroups: [
        {
          mode: 'and',
          filters: [
            { key: ['sightedBy'], values: ['aaa'], operator: 'not_eq' },
            { key: ['objectLabel'], values: ['label1-id'] },
            { key: ['publication_date'], values: ['random_date'] },
          ],
          filterGroups: [
            {
              mode: 'or',
              filters: [
                { key: ['value', 'name', 'objectMarking'], values: [], operator: 'nil' },
                { key: ['located-at', 'name', 'externalReferences'], values: ['aaa'] },
              ],
              filterGroups: [],
            }
          ],
        },
      ],
    } as FilterGroup;
    const expectedFilter = {
      mode: 'or',
      filters: [
        { key: ['rel_related-to.*'], values: ['xxx'], operator: 'eq', mode: 'or' },
        { key: ['context_data.id'], values: ['YYY'] },
        { key: ['user_id'], values: ['ZZZ'] },
      ],
      filterGroups: [
        {
          mode: 'and',
          filters: [
            { key: ['rel_stix-sighting-relationship.internal_id'], values: ['aaa'], operator: 'not_eq' },
            { key: ['rel_object-label.*'], values: ['label1-id'] },
            { key: ['publication_date'], values: ['random_date'] },
          ],
          filterGroups: [
            {
              mode: 'or',
              filters: [
                { key: ['value', 'name', 'rel_object-marking.*'], values: [], operator: 'nil' },
                { key: ['rel_located-at.*', 'name', 'rel_external-reference.*'], values: ['aaa'] },
              ],
              filterGroups: [],
            }
          ],
        }
      ],
    };
    const newFilter = convertRelationRefsFilterKeys(filterGroup);
    expect(newFilter).toEqual(expectedFilter);
  });
  it('should extract the filter values corresponding to a given array of filter keys', async () => {
    const filterGroup1 = {
      mode: 'or',
      filters: [
        { key: ['entity_type'], values: ['Report'], operator: 'eq', mode: 'or' },
        { key: ['publication_date'], values: ['YYY'] },
      ],
      filterGroups: [],
    } as FilterGroup;
    expect(extractFilterGroupValues(filterGroup1, 'entity_type')).toStrictEqual(['Report']);
    const filterGroup2 = {
      mode: 'or',
      filters: [
        { key: ['entity_type'], values: ['Report'], operator: 'eq', mode: 'or' },
        { key: ['publication_date'], values: ['YYY'], operator: 'gt' },
      ],
      filterGroups: [
        {
          mode: 'and',
          filters: [
            { key: ['entity_type', 'parent_types'], values: ['City', 'Region'], operator: 'not_eq', mode: 'and' },
            { key: 'objectLabel', values: ['label1'] },
            { key: 'objectMarking', values: ['marking1'] },
          ]
        }
      ],
    } as FilterGroup;
    expect(extractFilterGroupValues(filterGroup2, ['entity_type', 'objectMarking'])).toStrictEqual(['Report', 'City', 'Region', 'marking1']);
    const filterGroup3 = {
      mode: 'or',
      filters: [
        { key: ['entity_type'], values: ['Report'], operator: 'eq', mode: 'or' },
        { key: ['publication_date'], values: ['YYY'], operator: 'gt' },
      ],
      filterGroups: [
        {
          mode: 'and',
          filters: [
            { key: ['entity_type'], values: ['City', 'Region'], operator: 'not_eq', mode: 'and' },
            { key: ['objectLabel'], values: ['label1'] },
            { key: 'objectMarking', values: ['marking1'] },
          ]
        }
      ],
    } as FilterGroup;
    expect(extractFilterGroupValues(filterGroup3, ['entity_type'], true)).toStrictEqual(['YYY', 'label1', 'marking1']);
    const filterGroup4 = {
      mode: 'or',
      filters: [
        { key: ['entity_type'], values: ['Report'], operator: 'eq', mode: 'or' },
        { key: ['publication_date'], values: ['YYY'], operator: 'gt' },
      ],
      filterGroups: [
        {
          mode: 'and',
          filters: [
            { key: 'entity_type', values: ['City', 'Region'], operator: 'not_eq', mode: 'and' },
            { key: ['objectLabel'], values: ['label1'] },
            { key: 'regardingOf',
              values: [
                { key: 'relationship_type', values: ['related-to'] },
                { key: 'id', values: ['id1', 'id2'] },
              ],
            },
          ]
        }
      ],
    } as FilterGroup;
    expect(extractFilterGroupValues(filterGroup4, ['objectLabel', 'regardingOf'])).toStrictEqual(['label1', 'id1', 'id2']);
  });
});
