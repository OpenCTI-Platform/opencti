import { afterEach, describe, expect, it, vi } from 'vitest';
import { Link } from 'react-router-dom';
import MenuItem from '@mui/material/MenuItem';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import { screen } from '@testing-library/react';
import testRender, { createMockUserContext } from '../../../utils/tests/test-render';
import useCustomViewTabs from './useCustomViewTabs';
import { CUSTOM_VIEW_TAB_VALUE } from './useCustomViews';
import { DropDownMenu, TabWithDropDownMenu } from '../../../components/TabWithDropDownMenu';
import { useCustomViewsData } from './useCustomViewsData';

vi.mock('./useCustomViewsData', () => ({
  useCustomViewsData: vi.fn().mockImplementation(() => ({
    allCustomViews: [],
    refetchCustomViews: () => ({ dispose: () => {} }),
  })),
}));

interface TestWrapperProps {
  entityType: string;
  basePath: string;
}

const TestWrapper = ({ entityType, basePath }: TestWrapperProps) => {
  const {
    customViews,
    displayMode,
    dropDownMenuState,
    currentCustomViewTab,
  } = useCustomViewTabs({ entityType, basePath });

  const { anchorEl, onOpen, onClose, isOpen } = dropDownMenuState;

  const renderMenuItems = () => customViews.map(({ id, name, path }) => (
    <MenuItem
      key={id}
      role="link"
      component={Link}
      to={`${basePath}/${path}`}
      selected={currentCustomViewTab === path}
    >
      {name}
    </MenuItem>
  ));

  const renderCustomViewTab = () => {
    if (displayMode.others === 'single') {
      return (
        <Tab
          component={Link}
          to={customViews[0].path}
          value={CUSTOM_VIEW_TAB_VALUE}
          label={customViews[0].name}
        />
      );
    }

    if (displayMode.others === 'dropdown') {
      return (
        <TabWithDropDownMenu
          value={CUSTOM_VIEW_TAB_VALUE}
          label="Custom view"
          isOpen={isOpen}
          onOpen={onOpen}
        />
      );
    }

    return null;
  };

  return (
    <>
      <Tabs value={currentCustomViewTab || false}>
        {renderCustomViewTab()}
      </Tabs>
      {displayMode.others === 'dropdown' && (
        <DropDownMenu
          anchorEl={anchorEl}
          isOpen={isOpen}
          onClose={onClose}
          renderMenuItems={renderMenuItems}
        />
      )}
    </>
  );
};

describe('useCustomViewTabs', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });
  it('renders another tab when custom view available', () => {
    vi.mocked(useCustomViewsData).mockImplementation(() => ({
      allCustomViews: [{
        id: '1504f07b-ee3f-4c09-ae66-b9550eb3abe3',
        name: customViewDisplayName,
        path: customViewPath,
        targetEntityType: 'Intrusion-Set',
        enabled: true,
        default: false,
      }],
      refetchCustomViews: () => ({ dispose: () => {} }),
    }));
    const customViewDisplayName = 'My custom view';
    const customViewPath = 'some-path';
    testRender(
      <TestWrapper entityType="Intrusion-Set" basePath="" />,
      {
        userContext: createMockUserContext({
          settings: {
            platform_feature_flags: [{
              id: 'CUSTOM_VIEW',
              enable: true,
            }],
          },
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
    vi.mocked(useCustomViewsData).mockImplementation(() => ({
      allCustomViews: [{
        id: '1504f07b-ee3f-4c09-ae66-b9550eb3abe3',
        name: 'My first custom view',
        path: 'some-path',
        targetEntityType: 'Intrusion-Set',
        enabled: true,
        default: false,
      }, {
        id: '90ebf22f-2c36-4836-b21a-e114ed4ca2ab',
        name: 'My second custom view',
        path: 'some-other-path',
        targetEntityType: 'Intrusion-Set',
        enabled: true,
        default: false,
      }],
      refetchCustomViews: () => ({ dispose: () => {} }),
    }));
    const { user } = testRender(
      <TestWrapper entityType="Intrusion-Set" basePath="" />,
      {
        userContext: createMockUserContext({
          settings: {
            platform_feature_flags: [{
              id: 'CUSTOM_VIEW',
              enable: true,
            }],
          },
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

  it('does not render another tab when custom view available but for other entity type', () => {
    const customViewDisplayName = 'My custom view';
    const customViewPath = 'some-path';
    vi.mocked(useCustomViewsData).mockImplementation(() => ({
      allCustomViews: [{
        id: '1504f07b-ee3f-4c09-ae66-b9550eb3abe3',
        name: customViewDisplayName,
        path: customViewPath,
        targetEntityType: 'Intrusion-Set',
        enabled: true,
        default: false,
      }],
      refetchCustomViews: () => ({ dispose: () => {} }),
    }));
    testRender(
      <TestWrapper entityType="Case-Rft" basePath="" />,
      {
        userContext: createMockUserContext({
          settings: {
            platform_feature_flags: [{
              id: 'CUSTOM_VIEW',
              enable: true,
            }],
          },
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

  it('does not render another tab when custom view exists but is disabled', () => {
    const customViewDisplayName = 'My custom view';
    const customViewPath = 'some-path';
    vi.mocked(useCustomViewsData).mockImplementation(() => ({
      allCustomViews: [{
        id: '1504f07b-ee3f-4c09-ae66-b9550eb3abe3',
        name: customViewDisplayName,
        path: customViewPath,
        enabled: false,
        default: false,
      }],
      refetchCustomViews: () => ({ dispose: () => {} }),
    }));
    testRender(
      <TestWrapper entityType="Intrusion-Set" basePath="" />,
      {
        userContext: createMockUserContext({
          settings: {
            platform_feature_flags: [{
              id: 'CUSTOM_VIEW',
              enable: true,
            }],
          },
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
