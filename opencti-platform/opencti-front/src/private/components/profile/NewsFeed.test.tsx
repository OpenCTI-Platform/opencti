import React from 'react';
import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, screen } from '@testing-library/react';
import { DataTableProps } from '../../../components/dataGrid/dataTableTypes';
import testRender, { createMockUserContext } from '../../../utils/tests/test-render';
import NewsFeed from './NewsFeed';

const HUB_URL = 'https://hub.filigran.io';
const SETTINGS_ID = 'settings-id-1';
const USER_ID = 'user-1';

const mockCommitMarkAllAsRead = vi.fn();
const mockLoadQuery = vi.fn();

let queryRef: unknown = { fake: 'query-ref' };

/** Props received by the mocked data table, to assert on the configuration built by NewsFeed. */
type CapturedDataTableProps = DataTableProps & { availableEntityTypes?: string[] };

let dataTableProps: CapturedDataTableProps | undefined;

/** Both the added and the deleted subscription callbacks, in mount order. */
let subscriptionCallbacks: (() => void)[] = [];

vi.mock('react-relay', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-relay')>();
  return {
    ...actual,
    useMutation: () => [mockCommitMarkAllAsRead, false],
    useSubscription: (config: { onNext: () => void }) => {
      subscriptionCallbacks.push(config.onNext);
    },
  };
});

vi.mock('../../../utils/hooks/useQueryLoading', () => ({
  useQueryLoadingWithLoadQuery: () => [queryRef, mockLoadQuery],
}));

vi.mock('../../../components/dataGrid/DataTable', () => ({
  default: (props: CapturedDataTableProps) => {
    dataTableProps = props;
    return <div data-testid="data-table" />;
  },
}));

const renderNewsFeed = () => testRender(<NewsFeed />, {
  userContext: createMockUserContext({
    me: { id: USER_ID },
    settings: { id: SETTINGS_ID, platform_xtmhub_url: HUB_URL },
    schema: { filterKeysSchema: new Map() },
  }),
});

/** Renders the cell produced by a column of the data table, so it can be asserted on. */
const renderColumn = (columnId: string, data: Record<string, unknown>, helpers: Record<string, unknown> = {}) => {
  const column = dataTableProps?.dataColumns[columnId];
  return testRender(
    <>{column?.render?.(data, { fldt: (date: string) => `formatted-${date}`, ...helpers })}</>,
    { userContext: createMockUserContext({ settings: { id: SETTINGS_ID, platform_xtmhub_url: HUB_URL } }) },
  );
};

describe('NewsFeed', () => {
  beforeAll(() => {
    // TagsCell relies on ResizeObserver, which jsdom does not implement.
    vi.stubGlobal('ResizeObserver', class {
      observe() {}

      unobserve() {}

      disconnect() {}
    });
  });

  beforeEach(() => {
    vi.clearAllMocks();
    dataTableProps = undefined;
    subscriptionCallbacks = [];
    queryRef = { fake: 'query-ref' };
  });

  it('displays a loader while the query is not ready', () => {
    queryRef = null;
    const { container } = renderNewsFeed();
    expect(screen.queryByTestId('data-table')).not.toBeInTheDocument();
    expect(container.querySelector('svg')).toBeInTheDocument();
  });

  it('displays the data table once the query is ready', () => {
    renderNewsFeed();
    expect(screen.getByTestId('data-table')).toBeInTheDocument();
  });

  it('marks all the news feed items as read on mount', () => {
    renderNewsFeed();
    expect(mockCommitMarkAllAsRead).toHaveBeenCalledOnce();
    expect(mockCommitMarkAllAsRead).toHaveBeenCalledWith({ variables: {} });
  });

  it('restricts the news feed items to the news feed entity type', () => {
    renderNewsFeed();
    expect(dataTableProps?.contextFilters?.filters).toContainEqual(
      expect.objectContaining({ key: 'entity_type', values: ['NewsFeedItem'] }),
    );
    expect(dataTableProps?.availableEntityTypes).toEqual(['NewsFeedItem']);
  });

  it('restricts the news feed items to the connected user', () => {
    renderNewsFeed();
    expect(dataTableProps?.contextFilters?.filters).toContainEqual(
      expect.objectContaining({ key: 'user_id', values: [USER_ID] }),
    );
  });

  it('disables the selection and the navigation of the lines', () => {
    renderNewsFeed();
    expect(dataTableProps?.disableLineSelection).toBe(true);
    expect(dataTableProps?.disableNavigation).toBe(true);
  });

  it('declares the expected columns', () => {
    renderNewsFeed();
    expect(Object.keys(dataTableProps?.dataColumns ?? {})).toEqual(['type', 'title', 'creation_date', 'tags']);
  });

  it.each([
    ['type', true],
    ['title', true],
    ['creation_date', true],
    ['tags', false],
  ])('makes the %s column sortable: %s', (columnId, isSortable) => {
    renderNewsFeed();
    expect(dataTableProps?.dataColumns[columnId].isSortable).toBe(isSortable);
  });

  it('spreads the full width across the columns', () => {
    renderNewsFeed();
    const total = Object.values(dataTableProps?.dataColumns ?? {})
      .reduce((acc, column) => acc + (column.percentWidth ?? 0), 0);
    expect(total).toBe(100);
  });

  it.each([
    ['RESOURCE_PLAYBOOK', 'Playbook'],
    ['RESOURCE_SOMETHING_NEW', 'Unsupported type'],
  ])('renders "%s" as "%s" in the type column', (newsFeedType, label) => {
    renderNewsFeed();
    renderColumn('type', { news_feed_type: newsFeedType });
    expect(screen.getByText(label)).toBeInTheDocument();
  });

  it('renders the title in the title column', () => {
    renderNewsFeed();
    renderColumn('title', { title: 'Brand new dashboard' });
    expect(screen.getByText('Brand new dashboard')).toBeInTheDocument();
  });

  it('renders an empty title column when the item has no title', () => {
    renderNewsFeed();
    const { container } = renderColumn('title', { title: null });
    expect(container).not.toBeEmptyDOMElement();
    expect(container.textContent).toBe('');
  });

  it('formats the date in the creation date column', () => {
    renderNewsFeed();
    renderColumn('creation_date', { creation_date: '2024-01-15T10:00:00Z' });
    expect(screen.getByText('formatted-2024-01-15T10:00:00Z')).toBeInTheDocument();
  });

  // Element widths are always 0 in jsdom, so useChipOverflow always truncates
  // as soon as there are several tags: the first tag is kept and the others are
  // moved into the "+N" chip, whose tooltip lists them.
  it('renders the tags in lowercase in the tags column', () => {
    renderNewsFeed();
    renderColumn('tags', { tags: ['CTI', 'MALWARE'] });
    expect(screen.getByText('cti')).toBeInTheDocument();
    expect(screen.getByText('+1')).toBeInTheDocument();
    expect(screen.getByLabelText('malware')).toBeInTheDocument();
  });

  it('ignores the empty tags of the tags column', () => {
    renderNewsFeed();
    renderColumn('tags', { tags: ['CTI', null, undefined] });
    expect(screen.getAllByText('cti').length).toBeGreaterThan(0);
  });

  it('renders an empty tags column when the item has no tag', () => {
    renderNewsFeed();
    const { container } = renderColumn('tags', { tags: null });
    expect(container.textContent).toBe('');
  });

  it.each([
    ['RESOURCE_PLAYBOOK', 'LibraryBooksOutlinedIcon'],
    ['RESOURCE_SOMETHING_NEW', 'NotificationsOutlinedIcon'],
  ])('renders the icon matching type %s', (newsFeedType, testId) => {
    renderNewsFeed();
    const { container } = testRender(<>{dataTableProps?.icon?.({ news_feed_type: newsFeedType })}</>);
    expect(container.querySelector(`svg[data-testid="${testId}"]`)).toBeInTheDocument();
  });

  it('renders a link to the hub in the actions of a line', () => {
    renderNewsFeed();
    testRender(
      <>{dataTableProps?.actions?.({ metadata: [{ key: 'url_path', value: '/dashboards/1' }] })}</>,
      { userContext: createMockUserContext({ settings: { id: SETTINGS_ID, platform_xtmhub_url: HUB_URL } }) },
    );
    const link = screen.getByRole('link', { name: 'Open in XTM Hub' });
    expect(new URL(link.getAttribute('href') as string).pathname).toBe('/dashboards/1');
  });

  it('renders no action when the line has no url path', () => {
    renderNewsFeed();
    testRender(
      <>{dataTableProps?.actions?.({ metadata: [] })}</>,
      { userContext: createMockUserContext({ settings: { id: SETTINGS_ID, platform_xtmhub_url: HUB_URL } }) },
    );
    expect(screen.queryByRole('link')).not.toBeInTheDocument();
  });

  it.each([
    [0, 'added'],
    [1, 'deleted'],
  ])('refreshes the list when a news feed item is %s', (callbackIndex) => {
    renderNewsFeed();
    act(() => subscriptionCallbacks[callbackIndex]());
    expect(mockLoadQuery).toHaveBeenCalledWith(expect.anything(), { fetchPolicy: 'network-only' });
  });
});
