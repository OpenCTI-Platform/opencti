import React from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { act, screen } from '@testing-library/react';
import { DataTableProps, DataTableVariant } from '../../../components/dataGrid/dataTableTypes';
import testRender, { createMockUserContext } from '../../../utils/tests/test-render';
import NewsFeedGitHubReleases, { NewsFeedReleasesCount } from './NewsFeedGitHubReleases';

const HUB_URL = 'https://hub.filigran.io';
const SETTINGS_ID = 'settings-id-1';
const USER_ID = 'user-1';

const mockLoadQuery = vi.fn();
const mockCommitMarkAllAsRead = vi.fn();

let queryRef: unknown = { fake: 'query-ref' };

type CapturedDataTableProps = DataTableProps & { availableEntityTypes?: string[]; additionalHeaderButtons?: React.ReactNode[] };

let dataTableProps: CapturedDataTableProps | undefined;

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

const hubUserContext = () => createMockUserContext({ settings: { id: SETTINGS_ID, platform_xtmhub_url: HUB_URL } });

const renderReleases = () => testRender(<NewsFeedGitHubReleases />, {
  userContext: createMockUserContext({
    me: { id: USER_ID },
    settings: { id: SETTINGS_ID, platform_xtmhub_url: HUB_URL },
    schema: { filterKeysSchema: new Map() },
  }),
});

const renderColumn = (columnId: string, data: Record<string, unknown>) => {
  const column = dataTableProps?.dataColumns[columnId];
  return testRender(
    <>{column?.render?.(data, { ftdt: (date: string) => `formatted-${date}` })}</>,
    { userContext: hubUserContext() },
  );
};

describe('NewsFeedGitHubReleases', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    dataTableProps = undefined;
    subscriptionCallbacks = [];
    queryRef = { fake: 'query-ref' };
  });

  it('displays a loader while the query is not ready', () => {
    queryRef = null;
    renderReleases();
    expect(screen.queryByTestId('data-table')).not.toBeInTheDocument();
  });

  it('displays the data table once the query is ready', () => {
    renderReleases();
    expect(screen.getByTestId('data-table')).toBeInTheDocument();
  });

  it('restricts the items to the GitHub releases of the connected user', () => {
    renderReleases();
    const filters = dataTableProps?.contextFilters?.filters;
    expect(filters).toContainEqual(expect.objectContaining({ key: 'entity_type', values: ['NewsFeedItem'] }));
    expect(filters).toContainEqual(expect.objectContaining({ key: 'user_id', values: [USER_ID] }));
    expect(filters).toContainEqual(expect.objectContaining({ key: 'news_feed_type', values: ['GITHUB_RELEASE'], operator: 'eq' }));
    expect(dataTableProps?.availableEntityTypes).toEqual(['NewsFeedItem']);
  });

  it('disables the selection and the navigation of the lines', () => {
    renderReleases();
    expect(dataTableProps?.disableLineSelection).toBe(true);
    expect(dataTableProps?.disableNavigation).toBe(true);
  });

  it('displays an empty state message when there is no release', () => {
    renderReleases();
    expect(dataTableProps?.emptyStateMessage).toBe('No GitHub release has been received yet');
  });

  it('hides the column headers and the saved filters, as in the design', () => {
    renderReleases();
    expect(dataTableProps?.hideHeaders).toBe(true);
    expect(dataTableProps?.hideSavedFilters).toBe(true);
  });

  it('replaces the pagination by an infinite scroll, as in the design', () => {
    renderReleases();
    expect(dataTableProps?.variant).toBe(DataTableVariant.inline);
    expect(dataTableProps?.enableInfiniteScroll).toBe(true);
  });

  it('displays the number of releases on the right of the filters', () => {
    renderReleases();
    expect(dataTableProps?.additionalHeaderButtons).toHaveLength(1);
  });

  it('declares the type, version and date columns, in this order', () => {
    renderReleases();
    expect(Object.keys(dataTableProps?.dataColumns ?? {})).toEqual(['news_feed_type', 'version', 'creation_date']);
  });

  it('makes no column sortable, since there is no header to sort with', () => {
    renderReleases();
    Object.values(dataTableProps?.dataColumns ?? {}).forEach((column) => expect(column.isSortable).toBe(false));
  });

  it('spreads the full width across the columns', () => {
    renderReleases();
    const total = Object.values(dataTableProps?.dataColumns ?? {})
      .reduce((acc, column) => acc + (column.percentWidth ?? 0), 0);
    expect(total).toBe(100);
  });

  it('lists the nodes of the news feed items', () => {
    renderReleases();
    const nodes = dataTableProps?.resolvePath?.({ myNewsFeeds: { edges: [{ node: { id: 'item-1' } }, { node: { id: 'item-2' } }] } });
    expect(nodes).toEqual([{ id: 'item-1' }, { id: 'item-2' }]);
  });

  it('renders the icon of the news feed type at the start of each line', () => {
    renderReleases();
    const { container } = testRender(<>{dataTableProps?.icon?.({ news_feed_type: 'GITHUB_RELEASE' })}</>);
    expect(container.querySelector('svg')).toBeInTheDocument();
  });

  it('renders the release type in the type column, whatever the title', () => {
    renderReleases();
    renderColumn('news_feed_type', { title: 'OpenCTI 7.261014.0', news_feed_type: 'GITHUB_RELEASE' });
    expect(screen.getByText('GitHub release')).toBeInTheDocument();
    expect(screen.queryByText('OpenCTI 7.261014.0')).not.toBeInTheDocument();
  });

  it('renders the version as a link to the release, through the hub redirect', () => {
    renderReleases();
    renderColumn('version', { metadata: [{ key: 'url_path', value: 'redirect/news-feed/1' }, { key: 'product_version', value: '7.260309.0-lts.8' }] });
    const link = screen.getByRole('link', { name: '7.260309.0-lts.8' });
    const url = new URL(link.getAttribute('href') as string);
    expect(url.origin).toBe(HUB_URL);
    expect(url.pathname).toBe('/redirect/news-feed/1');
    expect(link).toHaveAttribute('target', '_blank');
    expect(link).toHaveAttribute('rel', 'noopener noreferrer');
  });

  it('renders the version as plain text when there is no url path', () => {
    renderReleases();
    renderColumn('version', { metadata: [{ key: 'product_version', value: '7.261014.0' }] });
    expect(screen.getByText('7.261014.0')).toBeInTheDocument();
    expect(screen.queryByRole('link', { name: '7.261014.0' })).not.toBeInTheDocument();
  });

  it('renders a placeholder in the version column when the version is missing', () => {
    renderReleases();
    const { container } = renderColumn('version', { metadata: [{ key: 'url_path', value: 'redirect/news-feed/1' }] });
    expect(container.querySelector('a')).not.toBeInTheDocument();
  });

  it('formats the creation date in the release date column', () => {
    renderReleases();
    renderColumn('creation_date', { creation_date: '2026-10-14T10:00:00Z' });
    expect(screen.getByText('formatted-2026-10-14T10:00:00Z')).toBeInTheDocument();
  });

  it('renders a link to the release, through the hub redirect, in the actions of a line', () => {
    renderReleases();
    testRender(
      <>{dataTableProps?.actions?.({ metadata: [{ key: 'url_path', value: 'redirect/news-feed/item-1' }] })}</>,
      { userContext: hubUserContext() },
    );
    const link = screen.getByRole('link', { name: 'Open the GitHub release' });
    const url = new URL(link.getAttribute('href') as string);
    expect(url.origin).toBe(HUB_URL);
    expect(url.pathname).toBe('/redirect/news-feed/item-1');
    expect(link).toHaveAttribute('target', '_blank');
    expect(link).toHaveAttribute('rel', 'noopener noreferrer');
  });

  it('renders no action when the line has no url path', () => {
    renderReleases();
    const { container } = testRender(
      <>{dataTableProps?.actions?.({ metadata: [] })}</>,
      { userContext: hubUserContext() },
    );
    expect(container.querySelector('a')).not.toBeInTheDocument();
  });

  it('renders a "See all releases" link to the GitHub releases page, without the hub redirect', () => {
    renderReleases();
    const link = screen.getByRole('link', { name: 'See all releases' });
    expect(link).toHaveAttribute('href', 'https://github.com/OpenCTI-Platform/opencti/releases');
    expect(link).toHaveAttribute('target', '_blank');
    expect(link).toHaveAttribute('rel', 'noopener noreferrer');
  });

  it('renders the "See all releases" link while the query is loading', () => {
    queryRef = null;
    renderReleases();
    expect(screen.getByRole('link', { name: 'See all releases' })).toBeInTheDocument();
  });

  it.each([
    [{ number: 14, symbol: '' }, '14 releases'],
    [{ number: 1, symbol: '' }, '1 release'],
    [{ number: 0, symbol: '' }, '0 releases'],
    [{ number: 1, symbol: 'K' }, '1K releases'],
    [{ number: 1.2, symbol: 'K' }, '1.2K releases'],
    [undefined, '0 releases'],
  ])('counts the releases as "%s"', (numberOfElements, expected) => {
    testRender(<NewsFeedReleasesCount numberOfElements={numberOfElements} />);
    expect(screen.getByText(expected)).toBeInTheDocument();
  });

  it('marks the GitHub releases as read on mount', () => {
    renderReleases();
    expect(mockCommitMarkAllAsRead).toHaveBeenCalledOnce();
    expect(mockCommitMarkAllAsRead).toHaveBeenCalledWith({ variables: {} });
  });

  it('marks the GitHub releases as read when one arrives while the tab is open', () => {
    renderReleases();
    mockCommitMarkAllAsRead.mockClear();
    act(() => subscriptionCallbacks[0]());
    expect(mockCommitMarkAllAsRead).toHaveBeenCalledOnce();
  });

  it('does not mark anything as read when a news feed item is deleted', () => {
    renderReleases();
    mockCommitMarkAllAsRead.mockClear();
    act(() => subscriptionCallbacks[1]());
    expect(mockCommitMarkAllAsRead).not.toHaveBeenCalled();
  });

  it.each([
    [0, 'added'],
    [1, 'deleted'],
  ])('refreshes the list when a news feed item is %s', (callbackIndex) => {
    renderReleases();
    act(() => subscriptionCallbacks[callbackIndex]());
    expect(mockLoadQuery).toHaveBeenCalledWith(expect.anything(), { fetchPolicy: 'network-only' });
  });
});
