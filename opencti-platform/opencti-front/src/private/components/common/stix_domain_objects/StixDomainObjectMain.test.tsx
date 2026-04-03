import { describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import { Route } from 'react-router-dom';
import testRender, { createMockUserContext } from '../../../../utils/tests/test-render';
import StixDomainObjectMain from './StixDomainObjectMain';
import { StixDomainObjectTabsBoxTab } from './StixDomainObjectTabsBox';

const CUSTOM_VIEW_MOCK_CONTENT = 'A great custom view page';

vi.mock('@components/custom_views/Root', () => ({
  default: () => <span>{CUSTOM_VIEW_MOCK_CONTENT}</span>,
  __esModule: true,
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
        entityType="Intrusion-Set"
        pages={{ [tab]: <span>{pageContent}</span> }}
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
        entityType="Intrusion-Set"
        pages={{}}
        basePath=""
        extraRoutes={<Route path={extraRoute} element={pageContent} />}
      />,
      {
        route: extraRoute,
      },
    );
    expect(screen.getByText(pageContent)).toBeInTheDocument();
  });

  it('renders 404 error for unknown route', () => {
    const nowhereRoute = '/nowhere';
    testRender(
      <StixDomainObjectMain
        entityType="Intrusion-Set"
        pages={{}}
        basePath=""
      />,
      {
        route: nowhereRoute,
      },
    );
    expect(screen.getByText(/This page is not found/i)).toBeInTheDocument();
  });

  describe('when CUSTOM_VIEW feature flag is enabled', () => {
    it('renders custom view when on custom view route', () => {
      const customViewPath = 'my-custom-view-1504f07bee3f4c09ae66b9550eb3abe3';
      testRender(
        <StixDomainObjectMain
          entityType="Intrusion-Set"
          pages={{}}
          basePath=""
        />,
        {
          route: customViewPath,
          userContext: createMockUserContext({
            settings: {
              platform_feature_flags: [{
                id: 'CUSTOM_VIEW',
                enable: true,
              }],
            },
            customViews: [{
              entity_type: 'Intrusion-Set',
              custom_views_info: [{
                id: '1504f07b-ee3f-4c09-ae66-b9550eb3abe3',
                name: 'My custom view',
                path: customViewPath,
              }],
            }],
          }),
        },
      );
      expect(screen.getByText(CUSTOM_VIEW_MOCK_CONTENT)).toBeInTheDocument();
    });
  });

  describe('when CUSTOM_VIEW feature flag is disabled', () => {
    it('renders error 404 when on custom view route', () => {
      const customViewPath = 'my-custom-view-1504f07bee3f4c09ae66b9550eb3abe3';
      testRender(
        <StixDomainObjectMain
          entityType="Intrusion-Set"
          pages={{}}
          basePath=""
        />,
        {
          route: customViewPath,
          userContext: createMockUserContext({
            settings: {
              platform_feature_flags: [{
                id: 'CUSTOM_VIEW',
                enable: false,
              }],
            },
            customViews: [{
              entity_type: 'Intrusion-Set',
              custom_views_info: [{
                id: '1504f07b-ee3f-4c09-ae66-b9550eb3abe3',
                name: 'My custom view',
                path: customViewPath,
              }],
            }],
          }),
        },
      );
      expect(screen.getByText(/This page is not found/i)).toBeInTheDocument();
    });
  });
});
