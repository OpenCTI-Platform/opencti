import React from 'react';
import { graphql } from 'react-relay';
import { ChannelsLines_data$data } from '@components/arsenal/__generated__/ChannelsLines_data.graphql';
import { ChannelsLinesPaginationQuery, ChannelsLinesPaginationQuery$variables } from '@components/arsenal/__generated__/ChannelsLinesPaginationQuery.graphql';
import ChannelCreation from './channels/ChannelCreation';
import Security from '../../../utils/Security';
import { KNOWLEDGE_KNPARTICIPATE, KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { emptyFilterGroup, useBuildEntityTypeBasedFilterContext, useGetDefaultFilterObject } from '../../../utils/filters/filtersUtils';
import Breadcrumbs from '../../../components/Breadcrumbs';
import { useFormatter } from '../../../components/i18n';
import DataTable from '../../../components/dataGrid/DataTable';
import { UsePreloadedPaginationFragment } from '../../../utils/hooks/usePreloadedPaginationFragment';
import useHelper from '../../../utils/hooks/useHelper';

const LOCAL_STORAGE_KEY = 'channels';

const channelLineFragment = graphql`
  fragment ChannelsLine_node on Channel {
    id
    entity_type
    name
    channel_types
    created
    modified
    confidence
    objectMarking {
      id
      definition_type
      definition
      x_opencti_order
      x_opencti_color
    }
    objectLabel {
      id
      value
      color
    }
  }
`;

const channelsLinesQuery = graphql`
  query ChannelsLinesPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: ChannelsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...ChannelsLines_data
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

const channelsLinesFragment = graphql`
  fragment ChannelsLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "ChannelsOrdering", defaultValue: name }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "ChannelsLinesRefetchQuery") {
    channels(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_channels") {
      edges {
        node {
          id
          name
          description
          ...ChannelsLine_node
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

const Channels = () => {
  const { t_i18n } = useFormatter();
  const { isFeatureEnable } = useHelper();
  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');

  const initialValues = {
    searchTerm: '',
    sortBy: 'name',
    orderAsc: true,
    openExports: false,
    filters: {
      ...emptyFilterGroup,
      filters: useGetDefaultFilterObject(['channel_types'], ['Channel']),
    },
  };
  const { viewStorage, helpers: storageHelpers, paginationOptions } = usePaginationLocalStorage<ChannelsLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    initialValues,
  );

  const {
    filters,
  } = viewStorage;

  const contextFilters = useBuildEntityTypeBasedFilterContext('Channel', filters);
  const queryPaginationOptions = {
    ...paginationOptions,
    filters: contextFilters,
  } as unknown as ChannelsLinesPaginationQuery$variables;

  const dataColumns = {
    name: {
      percentWidth: 30,
    },
    channel_types: {},
    objectLabel: {
      percentWidth: 20,
    },
    created: {},
    modified: {},
  };
  const queryRef = useQueryLoading<ChannelsLinesPaginationQuery>(
    channelsLinesQuery,
    queryPaginationOptions,
  );

  const preloadedPaginationProps = {
    linesQuery: channelsLinesQuery,
    linesFragment: channelsLinesFragment,
    queryRef,
    nodePath: ['channels', 'pageInfo', 'globalCount'],
    setNumberOfElements: storageHelpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<ChannelsLinesPaginationQuery>;

  return (
    <>
      <Breadcrumbs variant="list" elements={[{ label: t_i18n('Arsenal') }, { label: t_i18n('Channels'), current: true }]} />
      {queryRef && (
        <DataTable
          dataColumns={dataColumns}
          resolvePath={(data: ChannelsLines_data$data) => data.channels?.edges?.map((n) => n?.node)}
          storageKey={LOCAL_STORAGE_KEY}
          initialValues={initialValues}
          toolbarFilters={contextFilters}
          preloadedPaginationProps={preloadedPaginationProps}
          lineFragment={channelLineFragment}
          exportContext={{ entity_type: 'Channel' }}
          createButton={isFABReplaced && (
            <Security needs={[KNOWLEDGE_KNUPDATE, KNOWLEDGE_KNPARTICIPATE]}>
              <ChannelCreation paginationOptions={queryPaginationOptions} />
            </Security>
          )}
        />
      )}
      {!isFABReplaced && (
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <ChannelCreation paginationOptions={queryPaginationOptions} />
        </Security>
      )}
    </>
  );
};
export default Channels;
