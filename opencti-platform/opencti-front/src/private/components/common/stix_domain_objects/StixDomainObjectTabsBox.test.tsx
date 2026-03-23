import { describe, expect, it } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../../../../utils/tests/test-render';
import StixDomainObjectTabsBox from './StixDomainObjectTabsBox';

const TABS_TEST_DATA = [
  ['Overview', 'overview', ''],
  ['Knowledge', 'knowledge', '/knowledge'],
  ['Content', 'content', '/content'],
  ['Analyses', 'analyses', '/analyses'],
  ['Sightings', 'sightings', '/sightings'],
  ['Entities', 'entities', '/entities'],
  ['Observables', 'observables', '/observables'],
  ['Data', 'files', '/files'],
  ['History', 'history', '/history'],
] as const;

describe('StixDomainObjectTabsBox', () => {
  const entityId = 'entity-id';
  const entityType = 'entity-type';
  const basePath = `base/${entityType}`;
  it.each(TABS_TEST_DATA)('renders a %s link when %s prop is passed targeting %s', (tabName, prop, subroute) => {
    testRender(
      <StixDomainObjectTabsBox
        tabs={[prop]}
        entity={{
          id: entityId,
          entity_type: entityType,
        }}
        basePath={basePath}
      />,
    );
    const tabElem = screen.getByRole('tab', { name: new RegExp(tabName, 'i') });
    expect(tabElem).toBeInTheDocument();
    expect(tabElem).toHaveAttribute(
      'href',
      expect.stringMatching(new RegExp(`${basePath}/${entityId}${subroute}$`)),
    );
  });

  it('renders components passed as extraActions', () => {
    testRender(
      <StixDomainObjectTabsBox
        tabs={[]}
        entity={{
          id: entityId,
          entity_type: entityType,
        }}
        basePath={basePath}
        extraActions={<>Some Extra Action</>}
      />,
    );
    expect(screen.getByText(/some extra action/i)).toBeInTheDocument();
  });
});
