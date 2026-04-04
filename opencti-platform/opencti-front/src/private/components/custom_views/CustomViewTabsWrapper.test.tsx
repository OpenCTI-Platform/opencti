import { describe, expect, it } from 'vitest';
import Tabs from '@mui/material/Tabs';
import { screen } from '@testing-library/react';
import testRender, { createMockUserContext } from '../../../utils/tests/test-render';
import CustomViewTabsWrapper from './CustomViewTabsWrapper';

describe('CustomViewTabsWrapper', () => {
  it('renders another tab when custom view available', () => {
    const customViewDisplayName = 'My custom view';
    const customViewPath = 'some-path';
    testRender(
      <CustomViewTabsWrapper
        entityType="Intrusion-Set"
        basePath=""
        render={({ CustomViewsTab, CustomViewsDropDown, currentCustomViewTab }) => {
          return (
            <>
              <Tabs value={currentCustomViewTab}>
                {CustomViewsTab}
              </Tabs>
              {CustomViewsDropDown}
            </>
          );
        }}
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

  it('renders a "Custom view" tab when multiple custom views available', async () => {
    const { user } = testRender(
      <CustomViewTabsWrapper
        entityType="Intrusion-Set"
        basePath=""
        render={({ CustomViewsTab, CustomViewsDropDown, currentCustomViewTab }) => {
          return (
            <>
              <Tabs value={currentCustomViewTab}>
                {CustomViewsTab}
              </Tabs>
              {CustomViewsDropDown}
            </>
          );
        }}
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
    const tabElem = screen.getByRole('tab', { name: /Custom view/i });
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
      <CustomViewTabsWrapper
        entityType="Case-Rft"
        basePath=""
        render={({ CustomViewsTab, CustomViewsDropDown, currentCustomViewTab }) => {
          return (
            <>
              <Tabs value={currentCustomViewTab}>
                {CustomViewsTab}
              </Tabs>
              {CustomViewsDropDown}
            </>
          );
        }}
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
      name: /Custom view/i,
    })).not.toBeInTheDocument();
  });
});
