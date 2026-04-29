import { NewsFeedLine_node$data } from '@components/profile/__generated__/NewsFeedLine_node.graphql';
import { NewsFeedLines_data$data } from '@components/profile/__generated__/NewsFeedLines_data.graphql';
import { NewsFeedLinesPaginationQuery, NewsFeedLinesPaginationQuery$variables } from '@components/profile/__generated__/NewsFeedLinesPaginationQuery.graphql';
import { Alert, IconButton, Stack, Tooltip } from '@mui/material';
import { InsertChartOutlined, OpenInNewOutlined } from '@mui/icons-material';
import React, { FunctionComponent, Suspense, useContext } from 'react';
import { graphql, PreloadedQuery } from 'react-relay';
import { Link } from 'react-router-dom';
import Tag from '../../../components/common/tag/Tag';
import DataTable from '../../../components/dataGrid/DataTable';
import { DataTableProps } from '../../../components/dataGrid/dataTableTypes';
import { defaultRender } from '../../../components/dataGrid/dataTableUtils';
import { useFormatter } from '../../../components/i18n';
import Loader, { LoaderVariant } from '../../../components/Loader';
import { FilterGroup } from '../../../utils/filters/filtersHelpers-types';
import { emptyFilterGroup, isFilterGroupNotEmpty, useRemoveIdAndIncorrectKeysFromFilterGroupObject } from '../../../utils/filters/filtersUtils';
import useAuth, { UserContext } from '../../../utils/hooks/useAuth';
import { UseLocalStorageHelpers, usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import { UsePreloadedPaginationFragment } from '../../../utils/hooks/usePreloadedPaginationFragment';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import useChipOverflow from '../data/IngestionCatalog/components/card/usecases/useChipOverflow';

const LOCAL_STORAGE_KEY = 'newsFeed';

const newsFeedInitialValues = {
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

const newsFeedLineFragment = graphql`
  fragment NewsFeedLine_node on NewsFeedItem {
    id
    entity_type
    title
    news_feed_type
    tags
    metadata {
      key
      value
    }
    creation_date
  }
`;

const newsFeedLinesQuery = graphql`
  query NewsFeedLinesPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: NewsFeedItemsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...NewsFeedLines_data
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

const newsFeedLinesFragment = graphql`
  fragment NewsFeedLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "NewsFeedItemsOrdering", defaultValue: creation_date }
    orderMode: { type: "OrderingMode", defaultValue: desc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "NewsFeedLinesRefetchQuery") {
    myNewsFeeds(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_myNewsFeeds") {
      edges {
        node {
          id
          ...NewsFeedLine_node
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

const TagsCell: FunctionComponent<{ tags: readonly (string | null | undefined)[] }> = ({ tags }) => {
  const tagValues = tags.filter(Boolean) as string[];
  const { containerRef, chipRefs, visibleCount, shouldTruncate } = useChipOverflow(tagValues);
  const hiddenCount = tagValues.length - visibleCount;

  return (
    <div
      ref={containerRef}
      style={{ display: 'flex', flexWrap: 'nowrap', alignItems: 'center', overflow: 'hidden', width: '100%', position: 'relative', gap: 4, height: 20 }}
    >
      {/* Hidden measurement row */}
      <Stack direction="row" position="absolute" visibility="hidden" gap={0.5}>
        {tagValues.map((tag, index) => (
          <div
            key={tag}
            ref={(el) => {
              chipRefs.current[index] = el;
            }}
          >
            <Tag label={tag} />
          </div>
        ))}
      </Stack>

      {/* Visible tags + overflow tag in the same row */}
      <Stack direction="row" gap={0.5} overflow="hidden" alignItems="center">
        {tagValues.slice(0, visibleCount).map((tag) => (
          <Tag key={tag} label={tag.toLowerCase()} />
        ))}
        {shouldTruncate && hiddenCount > 0 && (
          <Tag
            label={`+${hiddenCount}`}
            tooltipTitle={tagValues.slice(visibleCount).map((tag) => tag.toLowerCase()).join(', ')}
            sx={{ flexShrink: 0, width: 'fit-content' }}
          />
        )}
      </Stack>
    </div>
  );
};

interface NewsFeedComponentProps {
  queryRef: PreloadedQuery<NewsFeedLinesPaginationQuery>;
  helpers: UseLocalStorageHelpers;
  contextFilters: FilterGroup;
}

const NewsFeedComponent: FunctionComponent<NewsFeedComponentProps> = ({ queryRef, helpers, contextFilters }) => {
  const { t_i18n } = useFormatter();
  const { settings } = useContext(UserContext);

  const dataColumns: DataTableProps['dataColumns'] = {
    type: {
      id: 'type',
      label: 'Type',
      percentWidth: 20,
      isSortable: true,
      render: ({ news_feed_type }: NewsFeedLine_node$data) => defaultRender(t_i18n(news_feed_type)),
    },
    title: {
      id: 'title',
      label: 'Title',
      percentWidth: 35,
      isSortable: true,
      render: ({ title }: NewsFeedLine_node$data) => (
        <div style={{ height: 20, fontSize: 13, float: 'left', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', paddingRight: 10 }}>
          <Tooltip title={title ?? ''}>
            <span>{title ?? ''}</span>
          </Tooltip>
        </div>
      ),
    },
    creation_date: {
      id: 'creation_date',
      label: 'Original creation date',
      percentWidth: 20,
      isSortable: true,
      render: ({ creation_date }: NewsFeedLine_node$data, item) => defaultRender(item.fldt(creation_date)),
    },
    tags: {
      id: 'tags',
      label: 'Tags',
      percentWidth: 25,
      isSortable: false,
      render: ({ tags }: NewsFeedLine_node$data) => (
        <TagsCell tags={tags ?? []} />
      ),
    },
  };

  const preloadedPaginationProps = {
    linesQuery: newsFeedLinesQuery,
    linesFragment: newsFeedLinesFragment,
    queryRef,
    nodePath: ['myNewsFeeds', 'pageInfo', 'globalCount'],
    setNumberOfElements: helpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<NewsFeedLinesPaginationQuery>;

  return (
    <div>
      <Alert severity="info" style={{ marginBottom: 16, backgroundColor: 'transparent', border: '1px solid #1976d2' }}>
        {t_i18n('Want to control which news appear here?')}{' '}
        <strong>{t_i18n('Manage your News Feed preferences')}</strong>{' '}
        {t_i18n('in your')}{' '}
        <Link to="/dashboard/profile/me">{t_i18n('profile settings')}</Link>.
      </Alert>
      <DataTable
        storageKey={LOCAL_STORAGE_KEY}
        initialValues={newsFeedInitialValues}
        preloadedPaginationProps={preloadedPaginationProps}
        resolvePath={(d: NewsFeedLines_data$data) => d.myNewsFeeds?.edges?.map((n) => n?.node)}
        dataColumns={dataColumns}
        icon={(row: NewsFeedLine_node$data) => (
          row.news_feed_type === 'RESOURCE_CUSTOM_DASHBOARD'
            ? <InsertChartOutlined fontSize="small" color="primary" />
            : null
        )}
        actions={(row) => {
          const item = row as NewsFeedLine_node$data;
          const urlPath = item.metadata?.find((m) => m?.key === 'url_path')?.value;
          const href = !!settings?.platform_xtmhub_url && urlPath ? new URL(urlPath, settings.platform_xtmhub_url).toString() : undefined;
          if (!href) return null;
          return (
            <Tooltip title={t_i18n('Open in XTM Hub')}>
              <IconButton
                component="a"
                href={href}
                target="_blank"
                rel="noopener noreferrer"
                onClick={(e: React.MouseEvent) => e.stopPropagation()}
              >
                <OpenInNewOutlined fontSize="small" color="primary" />
              </IconButton>
            </Tooltip>
          );
        }}
        lineFragment={newsFeedLineFragment}
        contextFilters={contextFilters}
        availableEntityTypes={['NewsFeedItem']}
        disableLineSelection
        disableNavigation
      />
    </div>
  );
};

const NewsFeed: FunctionComponent = () => {
  const { me } = useAuth();

  const {
    viewStorage,
    helpers,
    paginationOptions,
  } = usePaginationLocalStorage<NewsFeedLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    newsFeedInitialValues,
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
    ],
    filterGroups: userFilters && isFilterGroupNotEmpty(userFilters) ? [userFilters] : [],
  };

  const queryPaginationOptions = {
    ...paginationOptions,
    orderBy: 'creation_date',
    filters: contextFilters,
  } as unknown as NewsFeedLinesPaginationQuery$variables;

  const queryRef = useQueryLoading<NewsFeedLinesPaginationQuery>(
    newsFeedLinesQuery,
    queryPaginationOptions,
  );

  return queryRef ? (
    <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
      <NewsFeedComponent
        queryRef={queryRef}
        helpers={helpers}
        contextFilters={contextFilters}
      />
    </Suspense>
  ) : (
    <Loader variant={LoaderVariant.inElement} />
  );
};

export default NewsFeed;
