import { describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import { Route } from 'react-router-dom';
import testRender, { createMockUserContext } from '../../../../utils/tests/test-render';
import StixDomainObjectMain from './StixDomainObjectMain';
import { StixDomainObjectTabsBoxTab } from './StixDomainObjectTabsBox';

vi.mock('../../../components/custom_views/useCustomViewsData', () => ({
  useCustomViewsData: vi.fn().mockReturnValue({
    allCustomViews: [],
  }),
}));

const TABS_TEST_DATA = [
  ['Overview', 'overview'],
  ['Knowledge', 'knowledge'],
  ['Content', 'content'],
  ['Analyses', 'analyses'],
  ['Sightings', 'sightings'],
  ['Entities', 'entities'],
  ['Observables', 'observables'],
  ['Data', 'files'],
  ['History', 'history'],
] as const satisfies [string, StixDomainObjectTabsBoxTab][];

describe('StixDomainObjectMain', () => {
  it.each(TABS_TEST_DATA)('renders the %s page when clicking on the %s tab on the %s route', async (tabName, tab) => {
    const pageContent = `${tabName} page content !`;
    const { user } = testRender(
      <StixDomainObjectMain
        entity={{
          id: '856251e7-f040-4739-8dce-15b90027e4dd',
          entity_type: 'Intrusion-Set',
        }}
        pages={{ overview: 'overview', [tab]: <span>{pageContent}</span> }}
        basePath=""
      />,
      {
        route: '/',
      },
    );
    await user.click(screen.getByRole('tab', { name: new RegExp(tabName, 'i') }));
    expect(screen.getByText(pageContent)).toBeInTheDocument();
  });

  it('renders extra routes', () => {
    const pageContent = 'Extra route content !';
    const extraRoute = '/somewhere';
    testRender(
      <StixDomainObjectMain
        entity={{
          id: '856251e7-f040-4739-8dce-15b90027e4dd',
          entity_type: 'Intrusion-Set',
        }}
        pages={{ overview: 'overview' }}
        basePath=""
        extraRoutes={<Route path={extraRoute} element={pageContent} />}
      />,
      {
        route: extraRoute,
      },
    );
    expect(screen.getByText(pageContent)).toBeInTheDocument();
  });

  it('renders 404 error for unknown route when CUSTOM_VIEW flag is enabled', () => {
    const nowhereRoute = '/nowhere';
    testRender(
      <StixDomainObjectMain
        entity={{
          id: '856251e7-f040-4739-8dce-15b90027e4dd',
          entity_type: 'Intrusion-Set',
        }}
        pages={{ overview: 'overview' }}
        basePath=""
      />,
      {
        route: nowhereRoute,
        userContext: createMockUserContext({
          settings: {
            platform_feature_flags: [{
              enable: true,
              id: 'CUSTOM_VIEW',
            }],
          },
        }),
      },
    );
    expect(screen.getByText(/This page is not found/i)).toBeInTheDocument();
  });
});
