import { afterEach, describe, expect, it, vi } from 'vitest';
import { Link } from 'react-router-dom';
import { MenuItem, Tabs, TabsList, TabsMenuTrigger, TabsTrigger } from '@filigran/design-system';
import { screen } from '@testing-library/react';
import testRender from '../../../utils/tests/test-render';
import useCustomViewTabs from './useCustomViewTabs';
import { CUSTOM_VIEW_TAB_VALUE, DEFAULT_CUSTOM_VIEW_TAB_VALUE } from './useCustomViews';
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
    defaultCustomView,
    otherCustomViews,
    displayMode,
    currentCustomViewTab,
  } = useCustomViewTabs({ entityType, basePath });

  return (
    <Tabs value={currentCustomViewTab || ''} panels="external">
      <TabsList>
        {defaultCustomView ? (
          <TabsTrigger value={DEFAULT_CUSTOM_VIEW_TAB_VALUE} asChild>
            <Link to={defaultCustomView.path}>{defaultCustomView.name}</Link>
          </TabsTrigger>
        ) : null}
        {displayMode.others === 'single' && (
          <TabsTrigger value={CUSTOM_VIEW_TAB_VALUE} asChild>
            <Link to={otherCustomViews[0].path}>{otherCustomViews[0].name}</Link>
          </TabsTrigger>
        )}
        {displayMode.others === 'dropdown' && (
          <TabsMenuTrigger
            active={currentCustomViewTab === CUSTOM_VIEW_TAB_VALUE}
            menu={otherCustomViews.map(({ id, name, path }) => (
              <MenuItem key={id} selected={currentCustomViewTab === path} asChild>
                <Link to={`${basePath}/${path}`}>{name}</Link>
              </MenuItem>
            ))}
          >
            Custom view
          </TabsMenuTrigger>
        )}
      </TabsList>
    </Tabs>
  );
};

describe('useCustomViewTabs', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });
  it('renders another tab', () => {
    vi.mocked(useCustomViewsData).mockImplementation(() => ({
      allCustomViews: [{
        id: '1504f07b-ee3f-4c09-ae66-b9550eb3abe3',
        name: customViewDisplayName,
        path: customViewPath,
        targetEntityType: 'Intrusion-Set',
        default: false,
      }],
      refetchCustomViews: () => ({ dispose: () => {} }),
    }));
    const customViewDisplayName = 'My custom view';
    const customViewPath = 'some-path';
    testRender(<TestWrapper entityType="Intrusion-Set" basePath="" />);
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
        default: false,
      }, {
        id: '90ebf22f-2c36-4836-b21a-e114ed4ca2ab',
        name: 'My second custom view',
        path: 'some-other-path',
        targetEntityType: 'Intrusion-Set',
        default: false,
      }],
      refetchCustomViews: () => ({ dispose: () => {} }),
    }));
    const { user } = testRender(<TestWrapper entityType="Intrusion-Set" basePath="" />);
    const tabElem = screen.getByRole('button', { name: /Custom view/i });
    expect(tabElem).toHaveAttribute('aria-haspopup', 'menu');
    await user.click(tabElem);
    const firstLinkElem = await screen.findByRole('menuitem', { name: /My first custom view/i });
    expect(firstLinkElem).toHaveAttribute(
      'href',
      expect.stringMatching(/some-path$/),
    );
    const secondLinkElem = screen.getByRole('menuitem', { name: /My second custom view/i });
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
        default: false,
      }],
      refetchCustomViews: () => ({ dispose: () => {} }),
    }));
    testRender(<TestWrapper entityType="Case-Rft" basePath="" />);
    expect(screen.queryByRole('tab', {
      name: new RegExp(customViewDisplayName, 'i'),
    })).not.toBeInTheDocument();
    expect(screen.queryByRole('tab', {
      name: /Custom view/i,
    })).not.toBeInTheDocument();
  });

  it('renders a default and a "Custom view" tab with other values when multiple custom views available and one is default', async () => {
    vi.mocked(useCustomViewsData).mockImplementation(() => ({
      allCustomViews: [{
        id: '1504f07b-ee3f-4c09-ae66-b9550eb3abe3',
        name: 'My first custom view',
        path: 'some-path',
        targetEntityType: 'Intrusion-Set',
        default: false,
      }, {
        id: '90ebf22f-2c36-4836-b21a-e114ed4ca2ab',
        name: 'My second custom view',
        path: 'some-other-path',
        targetEntityType: 'Intrusion-Set',
        default: false,
      }, {
        id: '808605b9-7bb3-4578-9175-e1ca74600e34',
        name: 'My default custom view',
        path: 'default-path',
        targetEntityType: 'Intrusion-Set',
        default: true,
      }],
      refetchCustomViews: () => ({ dispose: () => {} }),
    }));
    const { user } = testRender(<TestWrapper entityType="Intrusion-Set" basePath="" />);
    const defaultTabElem = screen.getByRole('tab', { name: /My default custom view/i });
    expect(defaultTabElem).toBeInTheDocument();
    const othersTabElem = screen.getByRole('button', { name: /^Custom view$/i });
    expect(othersTabElem).toHaveAttribute('aria-haspopup', 'menu');
    await user.click(othersTabElem);
    const firstLinkElem = await screen.findByRole('menuitem', { name: /My first custom view/i });
    expect(firstLinkElem).toHaveAttribute(
      'href',
      expect.stringMatching(/some-path$/),
    );
    const secondLinkElem = screen.getByRole('menuitem', { name: /My second custom view/i });
    expect(secondLinkElem).toHaveAttribute(
      'href',
      expect.stringMatching(/some-other-path$/),
    );
  });
});
