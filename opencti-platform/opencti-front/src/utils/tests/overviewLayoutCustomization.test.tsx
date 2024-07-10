import { describe, it, expect } from 'vitest';
import { renderHook } from '@testing-library/react';
import React from 'react';
import useAuth from '../hooks/useAuth';
import { createMockUserContext, ProvidersWrapper, ProvidersWrapperProps } from './test-render';

describe('overviewLayoutCustomization', () => {
  const threatActorIndividualEntityType = 'Threat-Actor-Individual';
  const overviewLayoutCustomization = new Map();
  const threatActorIndividualConfiguration = new Map();
  threatActorIndividualConfiguration.set('details', { order: 1, width: 6 });
  threatActorIndividualConfiguration.set('basicInformation', { order: 2, width: 6 });
  threatActorIndividualConfiguration.set('demographics-biographics', { order: 3, width: 6 });
  threatActorIndividualConfiguration.set('latestCreatedRelationships', { order: 5, width: 6 });
  threatActorIndividualConfiguration.set('latestContainers', { order: 6, width: 6 });
  threatActorIndividualConfiguration.set('externalReferences', { order: 7, width: 6 });
  threatActorIndividualConfiguration.set('mostRecentHistory', { order: 8, width: 6 });
  threatActorIndividualConfiguration.set('notes', { order: 9, width: 12 });
  overviewLayoutCustomization.set(
    'Threat-Actor-Individual',
    threatActorIndividualConfiguration,
  );
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

  it('should provide order and width for every widget', () => {
    const threatActorIndividualOverviewLayoutCustomization = result.current?.overviewLayoutCustomization?.get(threatActorIndividualEntityType);
    expect(
      Array.from(threatActorIndividualOverviewLayoutCustomization?.values() ?? [])
        .every(({ order, width }) => !!order && !!width),
    ).toEqual(
      true,
    );
  });
});
