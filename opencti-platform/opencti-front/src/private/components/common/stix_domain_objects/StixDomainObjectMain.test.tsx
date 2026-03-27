import { describe, expect, it } from 'vitest';
import { screen } from '@testing-library/react';
import { Route } from 'react-router-dom';
import testRender from '../../../../utils/tests/test-render';
import StixDomainObjectMain from './StixDomainObjectMain';
import { StixDomainObjectTabsBoxTab } from './StixDomainObjectTabsBox';

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
        pages={{ [tab]: <span>{pageContent}</span> }}
        basePath=""
      />,
    );
    await user.click(screen.getByRole('tab', { name: new RegExp(tabName, 'i') }));
    expect(screen.getByText(pageContent)).toBeInTheDocument();
  });

  it('renders extra routes', () => {
    const pageContent = 'Extra route content !';
    const extraRoute = '/somewhere';
    testRender(
      <StixDomainObjectMain
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
});
