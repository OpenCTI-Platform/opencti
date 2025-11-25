import { describe, expect, it } from 'vitest';
import {
  buildFiltersAndOptionsForWidgets,
  emptyFilterGroup,
  findFiltersFromKeys,
  getEntityTypeTwoFirstLevelsFilterValues,
  isRegardingOfFilterWarning,
  removeIdAndIncorrectKeysFromFilterGroupObject,
  removeIdFromFilterGroupObject,
  serializeFilterGroupForBackend,
  useBuildFilterKeysMapFromEntityType,
} from './filtersUtils';
import { createMockUserContext, testRenderHook } from '../tests/test-render';
import filterKeysSchema from '../tests/FilterUtilsConstants';
import { FilterGroup } from './filtersHelpers-types';

describe('Filters utils', () => {
  describe('useBuildFilterKeysMapFromEntityType', () => {
    it('should list filter definitions by given entity types attributes', () => {
      const stixCoreObjectKey = 'Stix-Core-Object';
      const entityTypes = [stixCoreObjectKey];
      const { hook } = testRenderHook(
        () => useBuildFilterKeysMapFromEntityType(entityTypes),
        {
          userContext: createMockUserContext({
            schema: {
              scos: [{ id: '', label: '' }],
              sdos: [{ id: '', label: '' }],
              smos: [{ id: '', label: '' }],
              scrs: [{ id: '', label: '' }],
              schemaRelationsTypesMapping: new Map<string, readonly string[]>(),
              schemaRelationsRefTypesMapping: new Map<string, readonly { name: string, toTypes: string[] }[]>(),
              filterKeysSchema,
            },
          }),
        },
      );
      expect(hook.result.current).toStrictEqual(filterKeysSchema.get(stixCoreObjectKey));
    });
  });

  describe('removeIdFromFilterGroupObject', () => {
    it('should remove id from filters', () => {
      expect(removeIdFromFilterGroupObject(emptyFilterGroup)).toStrictEqual(emptyFilterGroup);
      const filters = {
        mode: 'and',
        filters: [
          { id: 'id-1', key: 'objectLabel', values: [], operator: 'nil' },
          { id: 'id-2', key: 'objectMarking', values: ['M1', 'M2'], operator: 'eq', mode: 'or' },
          { id: 'id-3',
            key: 'dynamicRegardingOf',
            values: [
              { key: 'false_key', values: ['test'] },
              { key: 'dynamic',
                values: [
                  { mode: 'and', filters: [{ id: 'id-3.1', key: 'entity_type', values: ['Malware'] }], filterGroups: [] },
                ],
              },
              { key: 'relationship_type', values: ['related-to'] },
            ],
          },
        ],
        filterGroups: [
          {
            mode: 'and',
            filters: [
              { id: 'id-4', key: ['creator_id'], values: ['XX'], operator: 'not_eq' },
            ],
            filterGroups: [],
          },
        ],
      };
      const filtersResult = {
        mode: 'and',
        filters: [
          { key: 'objectLabel', values: [], operator: 'nil' },
          { key: 'objectMarking', values: ['M1', 'M2'], operator: 'eq', mode: 'or' },
          { key: 'dynamicRegardingOf',
            values: [
              { key: 'dynamic',
                values: [
                  { mode: 'and', filters: [{ key: 'entity_type', values: ['Malware'] }], filterGroups: [] },
                ],
              },
              { key: 'relationship_type', values: ['related-to'] },
            ],
          },
        ],
        filterGroups: [
          {
            mode: 'and',
            filters: [
              { key: ['creator_id'], values: ['XX'], operator: 'not_eq' },
            ],
            filterGroups: [],
          },
        ],
      };
      expect(removeIdFromFilterGroupObject(filters as unknown as FilterGroup)).toStrictEqual(filtersResult);
    });
  });

  describe('removeIdAndIncorrectKeysFromFilterGroupObject', () => {
    it('should remove id and incorrect filter keys from filters', () => {
      const availableFilterKeys = ['objectLabel', 'objectMarking', 'creator_id', 'entity_type', 'dynamicRegardingOf', 'published'];
      const filters = {
        mode: 'and',
        filters: [
          { id: 'id-1', key: 'objectLabel', values: [], operator: 'nil' }, // id to remove
          { id: 'id-2', key: 'ids', values: ['i1', 'i2'], operator: 'eq', mode: 'or' }, // id to remove, key to keep because 'ids' is a not cleanable key
          { id: 'id-3', // id to remove
            key: 'dynamicRegardingOf',
            values: [
              { key: 'false_key', values: ['test'] }, // to remove because not authorized in dynamicRegardingOf filter
              { key: 'dynamic',
                values: [
                  { mode: 'and', filters: [{ id: 'id-3.1', key: 'entity_type', values: ['Malware'] }], filterGroups: [] },
                ],
              },
              { key: 'relationship_type', values: ['related-to'] },
            ],
          },
        ],
        filterGroups: [
          {
            mode: 'and',
            filters: [
              { id: 'id-4', key: 'creator_id', values: ['XX'], operator: 'not_eq' }, // id to remove
              { id: 'id-5', key: 'false_key', values: ['YY'] }, // to remove because key not in availableFilterKeys
            ],
            filterGroups: [],
          },
        ],
      };
      const filtersResult = {
        mode: 'and',
        filters: [
          { key: 'objectLabel', values: [], operator: 'nil' },
          { key: 'ids', values: ['i1', 'i2'], operator: 'eq', mode: 'or' },
          { key: 'dynamicRegardingOf',
            values: [
              { key: 'dynamic',
                values: [
                  { mode: 'and', filters: [{ key: 'entity_type', values: ['Malware'] }], filterGroups: [] },
                ],
              },
              { key: 'relationship_type', values: ['related-to'] },
            ],
          },
        ],
        filterGroups: [
          {
            mode: 'and',
            filters: [
              { key: 'creator_id', values: ['XX'], operator: 'not_eq' },
            ],
            filterGroups: [],
          },
        ],
      };
      expect(removeIdAndIncorrectKeysFromFilterGroupObject(filters as unknown as FilterGroup, availableFilterKeys)).toStrictEqual(filtersResult);
    });
  });

  describe('getEntityTypeTwoFirstLevelsFilterValues', () => {
    it('should return only observable subtypes when filter with AND Observables', () => {
      // filters: Observable AND Domain-Name
      // result: Domain-Name
      const filters = {
        mode: 'and',
        filters: [{ key: 'entity_type', operator: 'eq', values: ['Stix-Cyber-Observable'] }],
        filterGroups: [
          {
            mode: 'and',
            filters: [{ key: 'entity_type', operator: 'eq', values: ['Domain-Name'] }],
            filterGroups: [],
          },
        ],
      };
      const result = getEntityTypeTwoFirstLevelsFilterValues(filters, ['Domain-Name', 'File']);
      expect(result).toEqual(['Domain-Name']);
    });

    it('should return both the observable subtypes and observable when filter with OR Observables and filter groups', () => {
      // filters: Observable OR Domain-Name
      // result: Observable, Domain-Name
      const filters = {
        mode: 'or',
        filters: [{ key: 'entity_type', operator: 'eq', values: ['Stix-Cyber-Observable'] }],
        filterGroups: [
          {
            mode: 'and',
            filters: [
              { key: 'entity_type', operator: 'eq', values: ['Domain-Name'] },
            ],
            filterGroups: [],
          },
        ],
      };
      const result = getEntityTypeTwoFirstLevelsFilterValues(filters, ['Domain-Name', 'File'], ['Stix-Domain-Object']);
      expect(result).toEqual(['Stix-Cyber-Observable', 'Domain-Name']);
    });

    it('should return both the observable subtypes and observable when filter with OR Observables', () => {
      // filters: Domain-Name OR Observable
      // result: Domain-Name, Observable
      const filters = {
        mode: 'or',
        filters: [{ key: 'entity_type', operator: 'eq', values: ['Domain-Name', 'Stix-Cyber-Observable'] }],
        filterGroups: [],
      };
      const result = getEntityTypeTwoFirstLevelsFilterValues(filters, ['Domain-Name', 'File'], ['Stix-Domain-Object']);
      expect(result).toEqual(['Domain-Name', 'Stix-Cyber-Observable']);
    });

    it('should return only observable subtypes when filter with AND Observables and filter groups', () => {
      // filters: Observable AND (Domain-Name AND label=label1)
      // result: Domain-Name
      const filters = {
        mode: 'and',
        filters: [{ key: 'entity_type', operator: 'eq', values: ['Stix-Cyber-Observable'] }],
        filterGroups: [
          {
            mode: 'and',
            filters: [
              { key: 'entity_type', operator: 'eq', values: ['Domain-Name'] },
              { key: 'objectLabel', operator: 'eq', values: ['label1'] },
            ],
            filterGroups: [],
          },
        ],
      };
      const result = getEntityTypeTwoFirstLevelsFilterValues(filters, ['Domain-Name', 'File']);
      expect(result).toEqual(['Domain-Name']);
    });

    it('should return only observable when filter with OR Observables and filter groups', () => {
      // filters: Observable AND (Domain-Name OR label=label1)
      // result: Observable
      const filters = {
        mode: 'and',
        filters: [{ key: 'entity_type', operator: 'eq', values: ['Stix-Cyber-Observable'] }],
        filterGroups: [
          {
            mode: 'or',
            filters: [
              { key: 'entity_type', operator: 'eq', values: ['Domain-Name'] },
              { key: 'objectLabel', operator: 'eq', values: ['label1'] },
            ],
            filterGroups: [],
          },
        ],
      };
      const result = getEntityTypeTwoFirstLevelsFilterValues(filters, ['Domain-Name', 'File'], ['Report', 'Malware']);
      expect(result).toEqual(['Stix-Cyber-Observable']);
    });

    it('should return only observable subtypes when filter with AND Observables', () => {
      // filters: Observable AND (Domain-Name OR File)
      // result: Domain-Name, File
      const filters = {
        mode: 'and',
        filters: [
          { key: 'entity_type', operator: 'eq', values: ['Stix-Cyber-Observable'] },
        ],
        filterGroups: [
          {
            mode: 'and',
            filters: [
              { key: 'entity_type', operator: 'eq', values: ['Domain-Name', 'File'] },
            ],
            filterGroups: [],
          },
        ],
      };
      const result = getEntityTypeTwoFirstLevelsFilterValues(filters, ['Domain-Name', 'File'], ['Report', 'Malware']);
      expect(result).toEqual(['Domain-Name', 'File']);
    });

    it('should return only the domain subtype when filter with OR and only one type is provided', () => {
      // filters: Stix-Domain-Object AND Malware
      // result: Malware
      const filters = {
        mode: 'and',
        filters: [{ key: 'entity_type', operator: 'eq', values: ['Stix-Domain-Object'] }],
        filterGroups: [
          {
            mode: 'or',
            filters: [{ key: 'entity_type', operator: 'eq', values: ['Malware'] }],
            filterGroups: [],
          },
        ],
      };
      const result = getEntityTypeTwoFirstLevelsFilterValues(filters, ['Domain-Name', 'File'], ['Malware', 'Artifact', 'Country', 'City']);
      expect(result).toEqual(['Malware']);
    });

    it('should return all the types if several entity types filters', () => {
      // filters: Report AND Malware
      // result: Malware
      const filters = {
        mode: 'or',
        filters: [
          { key: 'entity_type', operator: 'eq', values: ['Report'] },
          { key: 'entity_type', operator: 'eq', values: ['Malware'] },
        ],
        filterGroups: [],
      };
      const result = getEntityTypeTwoFirstLevelsFilterValues(filters, [], ['Malware', 'Report', 'Country', 'City']);
      expect(result).toEqual(['Report', 'Malware']);
    });

    it('should return all the types if several entity types filters', () => {
      // filters: (Entity OR File) AND Malware
      // result: Malware
      const filters = {
        mode: 'and',
        filters: [
          { key: 'entity_type', operator: 'eq', values: ['Report', 'File'] },
          { key: 'entity_type', operator: 'eq', values: ['Malware'] },
        ],
        filterGroups: [],
      };
      const result = getEntityTypeTwoFirstLevelsFilterValues(filters, ['File'], ['Malware', 'Report', 'Country', 'City']);
      expect(result).toEqual(['Report', 'File', 'Malware']);
    });

    it('should return correct types if there are filter groups with no entity types', () => {
      // filters: (Malware) OR (label=label1 AND marking=marking1)
      // result: []
      const filters = {
        mode: 'or',
        filters: [
          { key: 'entity_type', operator: 'eq', values: ['Malware'] },
        ],
        filterGroups: [{
          mode: 'and',
          filters: [
            { key: 'objectLabel', operator: 'eq', values: ['label1-id'] },
            { key: 'objectMarking', operator: 'eq', values: ['marking1-id'] },
          ],
          filterGroups: [],
        }],
      };
      const result = getEntityTypeTwoFirstLevelsFilterValues(filters, [], []);
      expect(result).toEqual([]);
      // filters: (Malware) AND (label=label1 OR marking=marking1)
      // result: Malware
      const filters2 = {
        mode: 'and',
        filters: [
          { key: 'entity_type', operator: 'eq', values: ['Malware'] },
        ],
        filterGroups: [{
          mode: 'or',
          filters: [
            { key: 'objectLabel', operator: 'eq', values: ['label1-id'] },
            { key: 'objectMarking', operator: 'eq', values: ['marking1-id'] },
          ],
          filterGroups: [],
        }],
      };
      const result2 = getEntityTypeTwoFirstLevelsFilterValues(filters2, [], []);
      expect(result2).toEqual(['Malware']);
    });

    it('should return correct types if there are filter groups with entity types', () => {
      // filters: (Malware) OR (City AND label=label1 AND marking=marking1)
      // result: Malware, City
      const filters = {
        mode: 'or',
        filters: [
          { key: 'entity_type', operator: 'eq', values: ['Malware'] },
        ],
        filterGroups: [{
          mode: 'and',
          filters: [
            { key: 'entity_type', operator: 'eq', values: ['City'] },
            { key: 'objectLabel', operator: 'eq', values: ['label1-id'] },
            { key: 'objectMarking', operator: 'eq', values: ['marking1-id'] },
          ],
          filterGroups: [],
        }],
      };
      const result = getEntityTypeTwoFirstLevelsFilterValues(filters, [], []);
      expect(result).toEqual(['Malware', 'City']);
      // filters: (Malware) AND (City OR label=label1)
      // result: Malware
      const filters2 = {
        mode: 'and',
        filters: [
          { key: 'entity_type', operator: 'eq', values: ['Malware'] },
        ],
        filterGroups: [{
          mode: 'or',
          filters: [
            { key: 'entity_type', operator: 'eq', values: ['City'] },
            { key: 'objectLabel', operator: 'eq', values: ['label1-id'] },
          ],
          filterGroups: [],
        }],
      };
      const result2 = getEntityTypeTwoFirstLevelsFilterValues(filters2, [], []);
      expect(result2).toEqual(['Malware']);
    });

    it('should return correct types if there are filter groups with sub entity types', () => {
      // filters: (Stix-Cyber-Observable) AND (File OR label=label1)
      // result: Stix-Cyber-Observable
      const filters = {
        mode: 'and',
        filters: [
          { key: 'entity_type', operator: 'eq', values: ['Stix-Cyber-Observable'] },
        ],
        filterGroups: [{
          mode: 'or',
          filters: [
            { key: 'entity_type', operator: 'eq', values: ['File'] },
            { key: 'objectLabel', operator: 'eq', values: ['label1-id'] },
          ],
          filterGroups: [],
        }],
      };
      const result = getEntityTypeTwoFirstLevelsFilterValues(filters, ['File', 'Domain-Name'], []);
      expect(result).toEqual(['Stix-Cyber-Observable']);
      // filters: (Stix-Cyber-Observable) AND (File)
      // result: File
      const filters2 = {
        mode: 'and',
        filters: [
          { key: 'entity_type', operator: 'eq', values: ['Stix-Cyber-Observable'] },
        ],
        filterGroups: [{
          mode: 'or',
          filters: [
            { key: 'entity_type', operator: 'eq', values: ['File'] },
          ],
          filterGroups: [],
        }],
      };
      const result2 = getEntityTypeTwoFirstLevelsFilterValues(filters2, ['File', 'Domain-Name'], []);
      expect(result2).toEqual(['File']);
      // filters: (Stix-Cyber-Observable) OR (File AND label=label1)
      // result: Stix-Cyber-Observable
      const filters3 = {
        mode: 'or',
        filters: [
          { key: 'entity_type', operator: 'eq', values: ['Stix-Cyber-Observable'] },
        ],
        filterGroups: [{
          mode: 'and',
          filters: [
            { key: 'entity_type', operator: 'eq', values: ['File'] },
            { key: 'objectLabel', operator: 'eq', values: ['label1-id'] },
          ],
          filterGroups: [],
        }],
      };
      const result3 = getEntityTypeTwoFirstLevelsFilterValues(filters3, ['File', 'Domain-Name'], []);
      expect(result3).toEqual(['Stix-Cyber-Observable', 'File']);
    });
  });
});

describe('Function findFilterFromKey: should return the filters of the specified keys among a filters list', () => {
  it('findFilterFromKey without specifying an operator', () => {
    const filtersList = [
      { key: 'value', values: [], operator: 'nil' },
      { key: 'name', values: ['name1', 'name2'], operator: 'eq' },
    ];
    const result = findFiltersFromKeys(filtersList, ['value']);
    expect(result).toEqual([]);
  });
  it('findFilterFromKey with several results', () => {
    const filtersList = [
      { key: 'value', values: [], operator: 'nil' },
      { key: 'name', values: ['name1', 'name2'], operator: 'eq' },
      { key: 'name', values: ['name3'], operator: 'eq' },
    ];
    const result = findFiltersFromKeys(filtersList, ['name']);
    expect(result).toEqual([{ key: 'name', values: ['name1', 'name2'], operator: 'eq' },
      { key: 'name', values: ['name3'], operator: 'eq' }]);
  });
  it('findFilterFromKey with operator specified', () => {
    const filtersList = [
      { key: 'value', values: [], operator: 'nil' },
      { key: 'name', values: ['name1', 'name2'], operator: 'eq' },
    ];
    const result = findFiltersFromKeys(filtersList, ['value'], 'nil');
    expect(result).toEqual([{ key: 'value', values: [], operator: 'nil' }]);
  });
  it('findFilterFromKey with several keys', () => {
    const filtersList = [
      { key: 'value', values: ['value1'], operator: 'eq' },
      { key: 'created_at', values: ['XX', 'YY'], mode: 'or' },
      { key: 'created_at', values: ['ZZ'], operator: 'not_eq' },
      { key: 'name', values: ['name1', 'name2'], operator: 'eq' },
    ];
    const result = findFiltersFromKeys(filtersList, ['value', 'test', 'created_at']);
    expect(result).toEqual([{ key: 'value', values: ['value1'], operator: 'eq' },
      { key: 'created_at', values: ['XX', 'YY'], mode: 'or' }]);
  });
});

describe('Function serializeFilterGroupForBackend', () => {
  it('serializeFilterGroupForBackend: empty filter group', () => {
    const result = serializeFilterGroupForBackend(undefined);
    expect(result).toEqual(JSON.stringify(emptyFilterGroup));
  });
  it('serializeFilterGroupForBackend: complex filters', () => {
    const inputFilters = {
      mode: 'or',
      filters: [
        { id: 'XX', key: ['value'], values: ['value1'], operator: 'eq' },
        { key: 'name', values: ['name1, name2'] },
      ],
      filterGroups: [
        {
          mode: 'and',
          filters: [
            { id: 'YY', key: 'name', values: [], operator: 'nil' },
          ],
          filterGroups: [],
        },
      ],
    };
    const resultFilters = {
      mode: 'or',
      filters: [
        { key: ['value'], values: ['value1'], operator: 'eq' },
        { key: ['name'], values: ['name1, name2'] },
      ],
      filterGroups: [
        {
          mode: 'and',
          filters: [
            { key: ['name'], values: [], operator: 'nil' },
          ],
          filterGroups: [],
        },
      ],
    };
    const result = serializeFilterGroupForBackend(inputFilters as FilterGroup);
    expect(result).toEqual(JSON.stringify(resultFilters));
  });
});

describe('isRegardingOfFilterWarning', () => {
  it('should return if the filter combination is a warning one', () => {
    const filtersRepresentativesMap = new Map([
      ['reportId', { id: 'reportId', value: 'MyReport', entity_type: 'Report', color: 'red' }],
      ['malwareId', { id: 'malwareId', value: 'MyMalware', entity_type: 'Malware', color: 'red' }],
      ['observableId', { id: 'observableId', value: 'MyObservable', entity_type: 'Software', color: 'red' }],
      ['indicatorId', { id: 'indicatorId', value: 'MyIndicator', entity_type: 'Indicator', color: 'red' }],
    ]);
    const filter1 = { key: 'objectMarking', values: ['marking1'], operator: 'eq' };
    const isWarning1 = isRegardingOfFilterWarning(filter1, [], filtersRepresentativesMap);
    expect(isWarning1).toEqual(false);
    const filter2 = {
      key: 'regardingOf',
      values: [
        { key: 'relationship_type', values: ['targets'] },
      ],
    };
    const isWarning2 = isRegardingOfFilterWarning(filter2, [], filtersRepresentativesMap);
    expect(isWarning2).toEqual(false);
    const filter3 = {
      key: 'regardingOf',
      values: [
        { key: 'id', values: ['malwareId'] },
      ],
    };
    const isWarning3 = isRegardingOfFilterWarning(filter3, [], filtersRepresentativesMap);
    expect(isWarning3).toEqual(false);
    const filter5 = {
      key: 'regardingOf',
      values: [
        { key: 'relationship_type', values: ['targets'] },
        { key: 'id', values: ['reportId'] },
      ],
    };
    const isWarning5 = isRegardingOfFilterWarning(filter5, [], filtersRepresentativesMap);
    expect(isWarning5).toEqual(false);
    const filter6 = {
      key: 'regardingOf',
      values: [
        { key: 'relationship_type', values: ['related-to'] },
        { key: 'id', values: ['observableId'] },
      ],
    };
    const isWarning6 = isRegardingOfFilterWarning(filter6, ['Software', 'Domain-Name'], filtersRepresentativesMap);
    expect(isWarning6).toEqual(true);
    const filter7 = {
      key: 'regardingOf',
      values: [
        { key: 'relationship_type', values: ['uses', 'related-to'] },
        { key: 'id', values: ['reportId', 'observableId'] },
      ],
    };
    const isWarning7 = isRegardingOfFilterWarning(filter7, ['Software', 'Domain-Name'], filtersRepresentativesMap);
    expect(isWarning7).toEqual(true);
    const filter8 = {
      key: 'regardingOf',
      values: [
        { key: 'relationship_type', values: ['indicates', 'related-to'] },
        { key: 'id', values: ['reportId'] },
      ],
    };
    const isWarning8 = isRegardingOfFilterWarning(filter8, ['Software', 'Domain-Name'], filtersRepresentativesMap);
    expect(isWarning8).toEqual(false);
    const filter9 = {
      key: 'regardingOf',
      values: [
        { key: 'relationship_type', values: ['indicates', 'related-to'] },
        { key: 'id', values: ['indicatorId'] },
      ],
    };
    const isWarning9 = isRegardingOfFilterWarning(filter9, ['Software', 'Domain-Name'], filtersRepresentativesMap);
    expect(isWarning9).toEqual(true);
  });
});

describe('buildFiltersAndOptionsForWidgets', () => {
  it('should return filters with start date', () => {
    const startDate = '2025-10-15T00:00:00+02:00';
    const inputFilters = {
      mode: 'and',
      filters: [{ key: 'entity_type', values: ['Report'] }],
      filterGroups: [
        {
          mode: 'or',
          filters: [
            { key: 'objectMarking', values: ['marking1'] },
            { key: 'entity_type', values: ['Country', 'City'] },
          ],
          filterGroups: [],
        },
      ],
    };
    const expectedFilters = {
      mode: 'and',
      filters: [{ key: 'created_at', values: [startDate], operator: 'gt', mode: 'or' }],
      filterGroups: [
        {
          mode: 'and',
          filters: [{ key: 'entity_type', values: ['Report'] }],
          filterGroups: [
            {
              mode: 'or',
              filters: [
                { key: 'objectMarking', values: ['marking1'] },
                { key: 'entity_type', values: ['Country', 'City'] },
              ],
              filterGroups: [],
            },
          ],
        },
      ],
    };
    const { filters } = buildFiltersAndOptionsForWidgets(inputFilters, { startDate });
    expect(filters).toStrictEqual(expectedFilters);
  });

  it('should return filters with start date, end date, and a date attribute', () => {
    const startDate = '2025-10-15T00:00:00+02:00';
    const endDate = '2025-10-21T00:00:00+02:00';
    const dateAttribute = 'modified';
    const inputFilters = {
      mode: 'and',
      filters: [{ key: 'entity_type', values: ['Report'] }],
      filterGroups: [],
    };
    const expectedFilters = {
      mode: 'and',
      filters: [
        { key: dateAttribute, values: [startDate], operator: 'gt', mode: 'or' },
        { key: dateAttribute, values: [endDate], operator: 'lt', mode: 'or' },
      ],
      filterGroups: [
        {
          mode: 'and',
          filters: [{ key: 'entity_type', values: ['Report'] }],
          filterGroups: [],
        },
      ],
    };
    const { filters } = buildFiltersAndOptionsForWidgets(inputFilters, { startDate, endDate, dateAttribute });
    expect(filters).toStrictEqual(expectedFilters);
  });

  it('should return filters for relationships widgets', () => {
    const inputFilters = {
      mode: 'and',
      filters: [{ key: 'createdBy', values: ['user1'] }],
      filterGroups: [],
    };
    const expectedFilters = {
      mode: 'and',
      filters: [{ key: 'entity_type', values: ['Stix-Core-Relationship', 'stix-sighting-relationship', 'object', 'object-label'], operator: 'eq', mode: 'or' }],
      filterGroups: [inputFilters],
    };
    const { filters } = buildFiltersAndOptionsForWidgets(inputFilters, { isKnowledgeRelationshipWidget: true });
    expect(filters).toStrictEqual(expectedFilters);
  });
});
