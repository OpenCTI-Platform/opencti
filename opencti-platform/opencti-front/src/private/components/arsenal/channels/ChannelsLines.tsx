import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery } from 'react-relay';
import { ChannelLine_node$data } from '@components/arsenal/channels/__generated__/ChannelLine_node.graphql';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { ChannelLine, ChannelLineDummy } from './ChannelLine';
import { DataColumns } from '../../../../components/list_lines';
import { HandleAddFilter, UseLocalStorageHelpers } from '../../../../utils/hooks/useLocalStorage';
import usePreloadedPaginationFragment from '../../../../utils/hooks/usePreloadedPaginationFragment';
import { ChannelsLinesPaginationQuery, ChannelsLinesPaginationQuery$variables } from './__generated__/ChannelsLinesPaginationQuery.graphql';
import { ChannelsLines_data$key } from './__generated__/ChannelsLines_data.graphql';

const nbOfRowsToLoad = 50;

interface ChannelsLinesProps {
  queryRef: PreloadedQuery<ChannelsLinesPaginationQuery>;
  dataColumns: DataColumns;
  paginationOptions?: ChannelsLinesPaginationQuery$variables;
  setNumberOfElements: UseLocalStorageHelpers['handleSetNumberOfElements'];
  selectedElements: Record<string, ChannelLine_node$data>;
  deSelectedElements: Record<string, ChannelLine_node$data>;
  onToggleEntity: (
    entity: ChannelLine_node$data,
    event: React.SyntheticEvent
  ) => void;
  selectAll: boolean;
  onLabelClick?: HandleAddFilter;
  redirectionMode?: string;
}

export const channelsLinesQuery = graphql`
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
    )}
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
          ...ChannelLine_node
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

const ChannelsLines: FunctionComponent<ChannelsLinesProps> = ({
  setNumberOfElements,
  queryRef,
  dataColumns,
  onToggleEntity,
  selectedElements,
  deSelectedElements,
  selectAll,
  paginationOptions,
  onLabelClick,
}) => {
  const { data, hasMore, loadMore, isLoadingMore } = usePreloadedPaginationFragment<
  ChannelsLinesPaginationQuery,
  ChannelsLines_data$key
  >({
    linesQuery: channelsLinesQuery,
    linesFragment: channelsLinesFragment,
    queryRef,
    nodePath: ['channels', 'pageInfo', 'globalCount'],
    setNumberOfElements,
  });

  return (
    <ListLinesContent
      initialLoading={!data}
      loadMore={loadMore}
      hasMore={hasMore}
      isLoading={isLoadingMore}
      dataList={data?.channels?.edges ?? []}
      globalCount={
        data?.channels?.pageInfo?.globalCount ?? nbOfRowsToLoad
      }
      LineComponent={ChannelLine}
      DummyLineComponent={ChannelLineDummy}
      dataColumns={dataColumns}
      nbOfRowsToLoad={nbOfRowsToLoad}
      paginationOptions={paginationOptions}
      onLabelClick={onLabelClick}
      selectedElements={selectedElements}
      deSelectedElements={deSelectedElements}
      selectAll={selectAll}
      onToggleEntity={onToggleEntity}
    />
  );
};

export default ChannelsLines;
