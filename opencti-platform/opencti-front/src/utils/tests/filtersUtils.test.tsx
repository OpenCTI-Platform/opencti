import { describe, it, expect } from 'vitest';
import {
  getEntityTypeTwoFirstLevelsFilterValues,
  useBuildFilterKeysMapFromEntityType,
  emptyFilterGroup,
  findFiltersFromKeys,
  serializeFilterGroupForBackend,
} from '../filters/filtersUtils';
import { createMockUserContext, testRenderHook } from './test-render';
import filterKeysSchema from './FilterUtilsConstants';
import { FilterGroup } from '../filters/filtersHelpers-types';

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
