import { describe, it, expect } from 'vitest';
import { renderHook } from '@testing-library/react';
import React from 'react';
import useAuth from '../hooks/useAuth';
import { createMockUserContext, ProvidersWrapper, ProvidersWrapperProps } from './test-render';

describe('overviewLayoutCustomization', () => {
  const threatActorIndividualEntityType = 'Threat-Actor-Individual';
  const wrapper = ({ children }: ProvidersWrapperProps) => {
    return (
      <ProvidersWrapper
        userContext={
          createMockUserContext()
        }
      >
        {children}
      </ProvidersWrapper>
    );
  };
  const { result } = renderHook(() => useAuth(), { wrapper });

  it('should provide overview layout customization settings by block for a given entity type', () => {
    const expectedWidgetsKeys = [
      'details',
      'basicInformation',
      'demographics-biographics',
      'latestCreatedRelationships',
      'latestContainers',
      'externalReferences',
      'mostRecentHistory',
      'notes',
    ];
    const threatActorIndividualOverviewLayoutCustomization = result.current?.overviewLayoutCustomization?.get(threatActorIndividualEntityType);
    expect(
      Array.from(threatActorIndividualOverviewLayoutCustomization?.keys() ?? []),
    ).toEqual(
      expectedWidgetsKeys,
    );
  });

  it('should provide width for every widget', () => {
    const threatActorIndividualOverviewLayoutCustomization = result.current?.overviewLayoutCustomization?.get(threatActorIndividualEntityType);
    expect(
      Array.from(threatActorIndividualOverviewLayoutCustomization?.values() ?? [])
        .every((width) => !!width),
    ).toEqual(
      true,
    );
  });
});
