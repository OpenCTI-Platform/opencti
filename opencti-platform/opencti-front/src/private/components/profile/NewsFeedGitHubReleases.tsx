import { NewsFeedGitHubReleasesLine_node$data } from './__generated__/NewsFeedGitHubReleasesLine_node.graphql';
import { NewsFeedGitHubReleasesLines_data$data } from './__generated__/NewsFeedGitHubReleasesLines_data.graphql';
import {
  NewsFeedGitHubReleasesLinesPaginationQuery,
  NewsFeedGitHubReleasesLinesPaginationQuery$variables,
} from './__generated__/NewsFeedGitHubReleasesLinesPaginationQuery.graphql';
import { Text, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import { OpenInNewOutlined } from '@mui/icons-material';
import Button from '@common/button/Button';
import IconButton from '@common/button/IconButton';
import React, { FunctionComponent, Suspense, useCallback, useEffect, useMemo } from 'react';
import { graphql, PreloadedQuery, useMutation, useSubscription } from 'react-relay';
import DataTable from '../../../components/dataGrid/DataTable';
import { DataTableProps, DataTableVariant } from '../../../components/dataGrid/dataTableTypes';
import { defaultRender } from '../../../components/dataGrid/dataTableUtils';
import { useFormatter } from '../../../components/i18n';
import Loader, { LoaderVariant } from '../../../components/Loader';
import { FilterGroup } from '../../../utils/filters/filtersHelpers-types';
import { emptyFilterGroup, isFilterGroupNotEmpty, useRemoveIdAndIncorrectKeysFromFilterGroupObject } from '../../../utils/filters/filtersUtils';
import useAuth from '../../../utils/hooks/useAuth';
import { NumberOfElements, UseLocalStorageHelpers, usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import { UsePreloadedPaginationFragment } from '../../../utils/hooks/usePreloadedPaginationFragment';
import { useQueryLoadingWithLoadQuery } from '../../../utils/hooks/useQueryLoading';
import { useXTMHubResourceLink } from '../../../utils/hooks/useXTMHubResourceLink';
import { getNewsFeedIcon, getNewsFeedMetadataValue, GITHUB_RELEASES_URL, NEWS_FEED_GITHUB_RELEASE_TYPE } from '../../../utils/NewsFeed';

const LOCAL_STORAGE_KEY = 'newsFeedGitHubReleases';

const newsFeedGitHubReleasesInitialValues = {
  searchTerm: '',
  sortBy: 'creation_date',
  orderAsc: false,
  filters: {
    ...emptyFilterGroup,
  },
  numberOfElements: {
    number: 0,
    symbol: '',
  },
};

const newsFeedGitHubReleasesLineFragment = graphql`
  fragment NewsFeedGitHubReleasesLine_node on NewsFeedItem {
    id
    entity_type
    news_feed_type
    metadata {
      key
      value
    }
    creation_date
  }
`;

const newsFeedGitHubReleasesLinesQuery = graphql`
  query NewsFeedGitHubReleasesLinesPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: NewsFeedItemsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...NewsFeedGitHubReleasesLines_data
    @arguments(
      search: $search
      count: $count
      cursor: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    )
  }
`;

const newsFeedGitHubReleasesLinesFragment = graphql`
  fragment NewsFeedGitHubReleasesLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "NewsFeedItemsOrdering", defaultValue: creation_date }
    orderMode: { type: "OrderingMode", defaultValue: desc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "NewsFeedGitHubReleasesLinesRefetchQuery") {
    myNewsFeeds(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "PaginationGitHubReleases_myNewsFeeds") {
      edges {
        node {
          id
          ...NewsFeedGitHubReleasesLine_node
        }
      }
      pageInfo {
        endCursor
        hasNextPage
        globalCount
      }
    }
  }
`;

const newsFeedGitHubReleasesItemSubscription = graphql`
  subscription NewsFeedGitHubReleasesSubscription {
    newsFeedItem {
      id
    }
  }
`;

const newsFeedGitHubReleasesItemDeletedSubscription = graphql`
  subscription NewsFeedGitHubReleasesDeletedSubscription {
    newsFeedItemDeleted
  }
`;

const newsFeedGitHubReleasesMarkAllAsReadMutation = graphql`
  mutation NewsFeedGitHubReleasesMarkAllAsReadMutation {
    markAllNewsFeedItemsAsRead(category: GITHUB_RELEASE)
  }
`;

const useGitHubReleaseLink = (data: NewsFeedGitHubReleasesLine_node$data) => {
  return useXTMHubResourceLink(getNewsFeedMetadataValue(data.metadata, 'url_path'));
};

const NewsFeedGitHubReleaseVersion: FunctionComponent<{ data: NewsFeedGitHubReleasesLine_node$data }> = ({ data }) => {
  const href = useGitHubReleaseLink(data);
  const version = getNewsFeedMetadataValue(data.metadata, 'product_version');

  if (!version) return defaultRender(version);

  const style = { fontWeight: 700, textDecoration: 'underline', color: 'inherit' };
  if (!href) return <span style={style}>{version}</span>;

  return (
    <a
      href={href}
      target="_blank"
      rel="noopener noreferrer"
      style={style}
    >
      {version}
    </a>
  );
};

const NewsFeedGitHubReleaseLineActions: FunctionComponent<{ data: NewsFeedGitHubReleasesLine_node$data }> = ({ data }) => {
  const { t_i18n } = useFormatter();
  const href = useGitHubReleaseLink(data);

  if (!href) return null;

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span style={{ display: 'inline-flex' }}>
          <IconButton
            component="a"
            href={href}
            target="_blank"
            rel="noopener noreferrer"
            size="small"
            aria-label={t_i18n('Open the GitHub release')}
          >
            <OpenInNewOutlined fontSize="small" color="primary" />
          </IconButton>
        </span>
      </TooltipTrigger>
      <TooltipContent>{t_i18n('Open the GitHub release')}</TooltipContent>
    </Tooltip>
  );
};

export const NewsFeedReleasesCount: FunctionComponent<{ numberOfElements?: NumberOfElements }> = ({ numberOfElements }) => {
  const { t_i18n } = useFormatter();
  const symbol = numberOfElements?.symbol ?? '';
  const count = numberOfElements?.number ?? 0;
  const label = count === 1 && !symbol
    ? t_i18n('1 release')
    : t_i18n('{count} releases', { values: { count: `${count}${symbol}` } });
  return (
    <Text variant="content-base" className="flex items-center whitespace-nowrap">
      {label}
    </Text>
  );
};

interface NewsFeedGitHubReleasesComponentProps {
  queryRef: PreloadedQuery<NewsFeedGitHubReleasesLinesPaginationQuery>;
  helpers: UseLocalStorageHelpers;
  contextFilters: FilterGroup;
  numberOfElements?: NumberOfElements;
  onNewItem: () => void;
}

const NewsFeedGitHubReleasesComponent: FunctionComponent<NewsFeedGitHubReleasesComponentProps> = ({
  queryRef,
  helpers,
  contextFilters,
  numberOfElements,
  onNewItem,
}) => {
  const { t_i18n } = useFormatter();

  const [commitMarkAllAsRead] = useMutation(newsFeedGitHubReleasesMarkAllAsReadMutation);
  useEffect(() => {
    commitMarkAllAsRead({ variables: {} });
  }, [commitMarkAllAsRead]);

  const subConfig = useMemo(() => ({
    subscription: newsFeedGitHubReleasesItemSubscription,
    variables: {},
    onNext: () => {
      commitMarkAllAsRead({ variables: {} });
      onNewItem();
    },
  }), [commitMarkAllAsRead, onNewItem]);
  useSubscription(subConfig);

  const deletedSubConfig = useMemo(() => ({
    subscription: newsFeedGitHubReleasesItemDeletedSubscription,
    variables: {},
    onNext: () => onNewItem(),
  }), [onNewItem]);
  useSubscription(deletedSubConfig);

  const dataColumns: DataTableProps['dataColumns'] = {
    news_feed_type: {
      id: 'news_feed_type',
      label: 'Type',
      percentWidth: 12,
      isSortable: false,
      render: ({ news_feed_type }: NewsFeedGitHubReleasesLine_node$data) => defaultRender(t_i18n(news_feed_type)),
    },
    version: {
      id: 'version',
      label: 'Version',
      percentWidth: 12,
      isSortable: false,
      render: (data: NewsFeedGitHubReleasesLine_node$data) => <NewsFeedGitHubReleaseVersion data={data} />,
    },
    creation_date: {
      id: 'creation_date',
      label: 'Release date',
      percentWidth: 76,
      isSortable: false,
      render: ({ creation_date }: NewsFeedGitHubReleasesLine_node$data, item) => defaultRender(item.ftdt(creation_date, 'long')),
    },
  };

  const preloadedPaginationProps = {
    linesQuery: newsFeedGitHubReleasesLinesQuery,
    linesFragment: newsFeedGitHubReleasesLinesFragment,
    queryRef,
    nodePath: ['myNewsFeeds', 'pageInfo', 'globalCount'],
    setNumberOfElements: helpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<NewsFeedGitHubReleasesLinesPaginationQuery>;

  return (
    <DataTable
      storageKey={LOCAL_STORAGE_KEY}
      initialValues={newsFeedGitHubReleasesInitialValues}
      preloadedPaginationProps={preloadedPaginationProps}
      resolvePath={(d: NewsFeedGitHubReleasesLines_data$data) => d.myNewsFeeds?.edges?.map((n) => n?.node)}
      dataColumns={dataColumns}
      icon={(row: NewsFeedGitHubReleasesLine_node$data) => {
        const Icon = getNewsFeedIcon(row.news_feed_type);
        return <Icon fontSize="small" color="primary" />;
      }}
      actions={(row: NewsFeedGitHubReleasesLine_node$data) => <NewsFeedGitHubReleaseLineActions data={row} />}
      lineFragment={newsFeedGitHubReleasesLineFragment}
      contextFilters={contextFilters}
      availableEntityTypes={['NewsFeedItem']}
      emptyStateMessage={t_i18n('No GitHub release has been received yet')}
      variant={DataTableVariant.inline}
      enableInfiniteScroll
      additionalHeaderButtons={[<NewsFeedReleasesCount key="count" numberOfElements={numberOfElements} />]}
      hideHeaders
      hideSavedFilters
      disableLineSelection
      disableNavigation
    />
  );
};

const NewsFeedGitHubReleases: FunctionComponent = () => {
  const { me } = useAuth();
  const { t_i18n } = useFormatter();

  const {
    viewStorage,
    helpers,
    paginationOptions,
  } = usePaginationLocalStorage<NewsFeedGitHubReleasesLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    newsFeedGitHubReleasesInitialValues,
  );

  const userFilters = useRemoveIdAndIncorrectKeysFromFilterGroupObject(viewStorage.filters, ['NewsFeedItem']);
  const contextFilters = {
    mode: 'and',
    filters: [
      {
        key: 'entity_type',
        values: ['NewsFeedItem'],
        operator: 'eq',
        mode: 'or',
      },
      {
        key: 'user_id',
        values: [me.id],
        operator: 'eq',
        mode: 'or',
      },
      {
        key: 'news_feed_type',
        values: [NEWS_FEED_GITHUB_RELEASE_TYPE],
        operator: 'eq',
        mode: 'or',
      },
    ],
    filterGroups: userFilters && isFilterGroupNotEmpty(userFilters) ? [userFilters] : [],
  };

  const queryPaginationOptions = {
    ...paginationOptions,
    filters: contextFilters,
  } as unknown as NewsFeedGitHubReleasesLinesPaginationQuery$variables;

  const [queryRef, loadQuery] = useQueryLoadingWithLoadQuery<NewsFeedGitHubReleasesLinesPaginationQuery>(
    newsFeedGitHubReleasesLinesQuery,
    queryPaginationOptions,
  );

  const handleNewItem = useCallback(() => {
    loadQuery(queryPaginationOptions, { fetchPolicy: 'network-only' });
  }, [loadQuery, queryPaginationOptions]);

  return (
    <div>
      {queryRef ? (
        <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
          <NewsFeedGitHubReleasesComponent
            queryRef={queryRef}
            helpers={helpers}
            contextFilters={contextFilters}
            numberOfElements={viewStorage.numberOfElements}
            onNewItem={handleNewItem}
          />
        </Suspense>
      ) : (
        <Loader variant={LoaderVariant.inElement} />
      )}
      <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 16 }}>
        <Button
          variant="secondary"
          component="a"
          href={GITHUB_RELEASES_URL}
          target="_blank"
          rel="noopener noreferrer"
        >
          {t_i18n('See all releases')}
        </Button>
      </div>
    </div>
  );
};

export default NewsFeedGitHubReleases;
