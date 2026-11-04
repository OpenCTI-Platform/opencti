import { act, screen, waitFor } from '@testing-library/react';
import { Route, Routes } from 'react-router';
import { MockPayloadGenerator } from 'relay-test-utils';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import testRender from '../../../../utils/tests/test-render';
import Root from './Root';

// Keep the indicator query and routing real, without mounting unrelated tabs.
vi.mock('./Indicator', () => ({ default: () => null }));
vi.mock('./IndicatorEdition', () => ({ default: () => null }));
vi.mock('./IndicatorDeletion', () => ({ default: () => null }));
vi.mock('./IndicatorKnowledge', () => ({ default: () => null }));
vi.mock('../../common/stix_core_objects/StixCoreObjectContentRoot', () => ({ default: () => null }));
vi.mock('../../common/stix_core_objects/StixCoreObjectHistory', () => ({ default: () => null }));
vi.mock('../../common/files/FileManager', () => ({ default: () => null }));
vi.mock('../../common/stix_domain_objects/StixDomainObjectHeader', () => ({ default: () => null }));
vi.mock('../../common/stix_domain_objects/StixDomainObjectTabsBox', () => ({ default: () => null }));
vi.mock('../../common/containers/StixCoreObjectOrStixCoreRelationshipContainers', () => ({ default: () => null }));
vi.mock('../../common/stix_core_relationships/StixCoreRelationshipCreationFromEntityHeader', () => ({ default: () => null }));
vi.mock('../../custom_views/CustomViewRedirector', () => ({ default: () => null }));
vi.mock('../../../../components/Breadcrumbs', () => ({ default: () => null }));

// This module otherwise preloads its query on the application environment at import time.
vi.mock('../../../../utils/hooks/useVocabularyCategory', () => ({ default: vi.fn() }));

vi.mock('../../events/stix_sighting_relationships/EntityStixSightingRelationships', () => ({
  default: ({ entityId, entityLink }: { entityId: string; entityLink: string }) => (
    <a href={entityLink}>{entityId}</a>
  ),
}));

const INTERNAL_ID = '0bbf25d8-54bb-4336-a624-994a14d1d8e3';
const STIX_ID = 'indicator--229d1255-1b4f-5665-9778-50304cd39fef';

describe('Indicator sightings route', () => {
  beforeEach(() => {
    vi.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('Unexpected network request'));
  });

  afterEach(() => {
    expect(globalThis.fetch).not.toHaveBeenCalled();
    vi.restoreAllMocks();
  });

  it.each([
    { name: 'STIX ID', routeId: STIX_ID },
    { name: 'internal ID', routeId: INTERNAL_ID },
  ])('uses the resolved indicator ID for sightings when the URL contains its $name', async ({ routeId }) => {
    const route = `/dashboard/observations/indicators/${routeId}/sightings`;
    const { relayEnv } = testRender(
      <Routes>
        <Route path="/dashboard/observations/indicators/:indicatorId/*" element={<Root />} />
      </Routes>,
      { route },
    );

    await waitFor(() => {
      expect(relayEnv.mock.getMostRecentOperation().request.node.params.name).toBe('RootIndicatorQuery');
    });
    const operation = relayEnv.mock.getMostRecentOperation();
    expect(operation.request.variables.id).toBe(routeId);

    await act(async () => {
      relayEnv.mock.resolve(operation, MockPayloadGenerator.generate(operation, {
        Indicator: () => ({
          id: INTERNAL_ID,
          standard_id: STIX_ID,
          entity_type: 'Indicator',
          name: 'Test indicator',
        }),
      }));
    });

    const sightings = await screen.findByRole('link');
    expect(sightings).toHaveTextContent(INTERNAL_ID);
    expect(sightings).toHaveAttribute('href', `/dashboard/observations/indicators/${routeId}/knowledge`);
    expect(window.location.pathname).toBe(route);
  });
});
