import { describe, expect, it } from 'vitest';
import { screen } from '@testing-library/react';
import testRender, { createMockUserContext } from '../../../../utils/tests/test-render';
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
  it.each(TABS_TEST_DATA)('renders a %s link when %s prop is passed targeting %s', (tabName, prop, subroute) => {
    testRender(
      <StixDomainObjectTabsBox
        entityType="Intrusion-Set"
        tabs={[prop]}
        basePath=""
      />,
    );
    const tabElem = screen.getByRole('tab', { name: new RegExp(tabName, 'i') });
    expect(tabElem).toBeInTheDocument();
    expect(tabElem).toHaveAttribute(
      'href',
      expect.stringMatching(new RegExp(`${subroute}$`)),
    );
  });

  it('renders components passed as extraActions', () => {
    testRender(
      <StixDomainObjectTabsBox
        entityType="Intrusion-Set"
        tabs={[]}
        basePath=""
        extraActions={<>Some Extra Action</>}
      />,
    );
    expect(screen.getByText(/some extra action/i)).toBeInTheDocument();
  });

  describe('when CUSTOM_VIEW feature flag is disabled', () => {
    it('does not render another tab when custom view available', () => {
      const customViewDisplayName = 'My custom view';
      const customViewPath = 'some-path';
      testRender(
        <StixDomainObjectTabsBox
          entityType="Intrusion-Set"
          tabs={[]}
          basePath=""
        />,
        {
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
                name: customViewDisplayName,
                path: customViewPath,
              }],
            }],
          }),
        },
      );
      expect(screen.queryByRole('tab', {
        name: new RegExp(customViewDisplayName, 'i'),
      })).not.toBeInTheDocument();
      expect(screen.queryByRole('tab', {
        name: /Custom views/i,
      })).not.toBeInTheDocument();
    });
  });

  describe('when CUSTOM_VIEW feature flag is enabled', () => {
    it('renders another tab when custom view available', () => {
      const customViewDisplayName = 'My custom view';
      const customViewPath = 'some-path';
      testRender(
        <StixDomainObjectTabsBox
          entityType="Intrusion-Set"
          tabs={[]}
          basePath=""
        />,
        {
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
                name: customViewDisplayName,
                path: customViewPath,
              }],
            }],
          }),
        },
      );
      const tabElem = screen.getByRole('tab', { name: new RegExp(customViewDisplayName, 'i') });
      expect(tabElem).toBeInTheDocument();
      expect(tabElem).toHaveAttribute(
        'href',
        expect.stringMatching(new RegExp(`${customViewPath}$`)),
      );
    });

    it('renders a "Custom views" tab when multiple custom views available', async () => {
      const { user } = testRender(
        <StixDomainObjectTabsBox
          entityType="Intrusion-Set"
          tabs={[]}
          basePath=""
        />,
        {
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
                name: 'My first custom view',
                path: 'some-path',
              }, {
                id: '90ebf22f-2c36-4836-b21a-e114ed4ca2ab',
                name: 'My second custom view',
                path: 'some-other-path',
              }],
            }],
          }),
        },
      );
      const tabElem = screen.getByRole('tab', { name: /Custom views/i });
      expect(tabElem).toBeInTheDocument();
      await user.click(tabElem);
      const firstLinkElem = screen.getByRole('link', { name: /My first custom view/i });
      expect(firstLinkElem).toHaveAttribute(
        'href',
        expect.stringMatching(/some-path$/),
      );
      const secondLinkElem = screen.getByRole('link', { name: /My second custom view/i });
      expect(secondLinkElem).toHaveAttribute(
        'href',
        expect.stringMatching(/some-other-path$/),
      );
    });

    it('does not renders another tab when custom view available but for other entity type', () => {
      const customViewDisplayName = 'My custom view';
      const customViewPath = 'some-path';
      testRender(
        <StixDomainObjectTabsBox
          entityType="Case-Rft"
          tabs={[]}
          basePath=""
        />,
        {
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
                name: customViewDisplayName,
                path: customViewPath,
              }],
            }],
          }),
        },
      );
      expect(screen.queryByRole('tab', {
        name: new RegExp(customViewDisplayName, 'i'),
      })).not.toBeInTheDocument();
      expect(screen.queryByRole('tab', {
        name: /Custom views/i,
      })).not.toBeInTheDocument();
    });
  });
});
