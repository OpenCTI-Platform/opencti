import { describe, it, expect } from 'vitest';
import { renderHook } from '@testing-library/react';
import React from 'react';
import { useBuildFilterKeysMapFromEntityType } from '../filters/filtersUtils';
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
});
