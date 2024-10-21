import { describe, it, expect } from 'vitest';
import { renderHook } from '@testing-library/react';
import React from 'react';
import { getEntityTypeTwoFirstLevelsFilterValues, useBuildFilterKeysMapFromEntityType } from '../filters/filtersUtils';
import { createMockUserContext, ProvidersWrapper, ProvidersWrapperProps } from './test-render';
import { BYPASS } from '../hooks/useGranted';
import filterKeysSchema from './FilterUtilsConstants';

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
  });
});
