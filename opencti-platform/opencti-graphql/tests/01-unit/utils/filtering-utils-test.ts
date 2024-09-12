import { describe, it, expect } from 'vitest';
import { addFilter, convertRelationRefsFilterKeys, replaceFilterKey } from '../../../src/utils/filtering/filtering-utils';
import type { FilterGroup } from '../../../src/generated/graphql';

describe('Filtering utils', () => {
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
});
