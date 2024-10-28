import { describe, it, expect } from 'vitest';
import { renderHook } from '@testing-library/react';
import React from 'react';
import { emptyFilterGroup, findFiltersFromKeys, serializeFilterGroupForBackend, useBuildFilterKeysMapFromEntityType } from '../filters/filtersUtils';
import { createMockUserContext, ProvidersWrapper, ProvidersWrapperProps } from './test-render';
import { BYPASS } from '../hooks/useGranted';
import filterKeysSchema from './FilterUtilsConstants';
import { FilterGroup } from '../filters/filtersHelpers-types';

describe('Filters utils', () => {
  describe('useBuildFilterKeysMapFromEntityType', () => {
    it('should list filter definitions by given entity types attributes', () => {
      const stixCoreObjectKey = 'Stix-Core-Object';
      const entityTypes = [stixCoreObjectKey];
      const wrapper = ({ children }: ProvidersWrapperProps) => {
        return (
          <ProvidersWrapper
            userContext={ createMockUserContext({
              me: {
                name: 'admin',
                user_email: 'admin@opencti.io',
                capabilities: [{ name: BYPASS }],
              },
              settings: undefined,
              bannerSettings: undefined,
              entitySettings: undefined,
              platformModuleHelpers: undefined,
              schema: {
                scos: [{ id: '', label: '' }],
                sdos: [{ id: '', label: '' }],
                smos: [{ id: '', label: '' }],
                scrs: [{ id: '', label: '' }],
                schemaRelationsTypesMapping: new Map<string, readonly string[]>(),
                schemaRelationsRefTypesMapping: new Map<string, readonly { name: string, toTypes: string[] }[]>(),
                filterKeysSchema,
              },
            })
            }
          >
            {children}
          </ProvidersWrapper>
        );
      };
      const { result } = renderHook(() => useBuildFilterKeysMapFromEntityType(entityTypes), { wrapper });
      expect(result.current).toStrictEqual(filterKeysSchema.get(stixCoreObjectKey));
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
