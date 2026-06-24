import { beforeEach, describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/react';
import testRender from '../../../../utils/tests/test-render';
import StixDomainObjectTabsBox from './StixDomainObjectTabsBox';

const { mockUseCustomViewTabs } = vi.hoisted(() => ({
  mockUseCustomViewTabs: vi.fn(),
}));

vi.mock('@components/custom_views/useCustomViewTabs', () => ({
  default: mockUseCustomViewTabs,
}));

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
  beforeEach(() => {
    mockUseCustomViewTabs.mockReturnValue({
      defaultCustomView: undefined,
      otherCustomViews: [],
      displayMode: {
        default: false,
        others: 'none',
      },
      dropDownMenuState: {
        anchorEl: null,
        onOpen: vi.fn(),
        onClose: vi.fn(),
        close: vi.fn(),
        isOpen: false,
      },
      currentCustomViewTab: undefined,
      currentCustomViewMenuItem: undefined,
    });
  });

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

  it('renders a default custom view tab link when one is available', () => {
    mockUseCustomViewTabs.mockReturnValue({
      defaultCustomView: {
        id: '20ee7b9d-fb42-4edf-8a3a-c966f41a6cb9',
        name: 'Default custom view',
        path: 'default-custom-view-20ee7b9d-fb42-4edf-8a3a-c966f41a6cb9',
        targetEntityType: 'Intrusion-Set',
        default: true,
      },
      otherCustomViews: [],
      displayMode: {
        default: true,
        others: 'none',
      },
      dropDownMenuState: {
        anchorEl: null,
        onOpen: vi.fn(),
        onClose: vi.fn(),
        close: vi.fn(),
        isOpen: false,
      },
      currentCustomViewTab: undefined,
      currentCustomViewMenuItem: undefined,
    });

    testRender(
      <StixDomainObjectTabsBox
        entityType="Intrusion-Set"
        tabs={[]}
        basePath=""
      />,
    );

    const tabElem = screen.getByRole('tab', { name: /default custom view/i });
    expect(tabElem).toBeInTheDocument();
    expect(tabElem).toHaveAttribute(
      'href',
      expect.stringMatching(/default-custom-view-20ee7b9d-fb42-4edf-8a3a-c966f41a6cb9$/),
    );
  });

  it('renders a single custom view tab link when in single display mode', () => {
    mockUseCustomViewTabs.mockReturnValue({
      defaultCustomView: undefined,
      otherCustomViews: [{
        id: '20ee7b9d-fb42-4edf-8a3a-c966f41a6cb9',
        name: 'Another custom view',
        path: 'another-custom-view-20ee7b9d-fb42-4edf-8a3a-c966f41a6cb9',
        targetEntityType: 'Intrusion-Set',
        default: false,
      }],
      displayMode: {
        default: false,
        others: 'single',
      },
      dropDownMenuState: {
        anchorEl: null,
        onOpen: vi.fn(),
        onClose: vi.fn(),
        close: vi.fn(),
        isOpen: false,
      },
      currentCustomViewTab: undefined,
      currentCustomViewMenuItem: undefined,
    });

    testRender(
      <StixDomainObjectTabsBox
        entityType="Intrusion-Set"
        tabs={[]}
        basePath=""
      />,
    );

    const tabElem = screen.getByRole('tab', { name: /another custom view/i });
    expect(tabElem).toBeInTheDocument();
    expect(tabElem).toHaveAttribute(
      'href',
      expect.stringMatching(/another-custom-view-20ee7b9d-fb42-4edf-8a3a-c966f41a6cb9$/),
    );
  });

  it('renders the custom view dropdown tab and menu items when in dropdown display mode', () => {
    mockUseCustomViewTabs.mockReturnValue({
      defaultCustomView: undefined,
      otherCustomViews: [{
        id: '20ee7b9d-fb42-4edf-8a3a-c966f41a6cb9',
        name: 'First custom view',
        path: 'first-custom-view-20ee7b9d-fb42-4edf-8a3a-c966f41a6cb9',
        targetEntityType: 'Intrusion-Set',
        default: false,
      }, {
        id: 'e9a6f2f9-354a-4a7b-9749-84f852e3d6d7',
        name: 'Second custom view',
        path: 'second-custom-view-e9a6f2f9-354a-4a7b-9749-84f852e3d6d7',
        targetEntityType: 'Intrusion-Set',
        default: false,
      }],
      displayMode: {
        default: false,
        others: 'dropdown',
      },
      dropDownMenuState: {
        anchorEl: document.body,
        onOpen: vi.fn(),
        onClose: vi.fn(),
        close: vi.fn(),
        isOpen: true,
      },
      currentCustomViewTab: undefined,
      currentCustomViewMenuItem: undefined,
    });

    testRender(
      <StixDomainObjectTabsBox
        entityType="Intrusion-Set"
        tabs={[]}
        basePath=""
      />,
    );

    const tabElem = screen.getByText(/^custom view$/i).closest('[role="tab"]');
    expect(tabElem).toBeInTheDocument();

    const firstLinkElem = screen.getByRole('link', { name: /first custom view/i });
    expect(firstLinkElem).toHaveAttribute(
      'href',
      expect.stringMatching(/first-custom-view-20ee7b9d-fb42-4edf-8a3a-c966f41a6cb9$/),
    );

    const secondLinkElem = screen.getByRole('link', { name: /second custom view/i });
    expect(secondLinkElem).toHaveAttribute(
      'href',
      expect.stringMatching(/second-custom-view-e9a6f2f9-354a-4a7b-9749-84f852e3d6d7$/),
    );
  });
});
