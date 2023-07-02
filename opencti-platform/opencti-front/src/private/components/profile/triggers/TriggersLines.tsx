import { GridTypeMap } from '@mui/material';
import React, { FunctionComponent, MutableRefObject } from 'react';
import { graphql, PreloadedQuery } from 'react-relay';
import { DataColumns } from '../../../../components/list_lines';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { UseLocalStorageHelpers } from '../../../../utils/hooks/useLocalStorage';
import usePreloadedPaginationFragment from '../../../../utils/hooks/usePreloadedPaginationFragment';
import { TriggersLines_data$key } from './__generated__/TriggersLines_data.graphql';
import { TriggersLinesPaginationQuery, TriggersLinesPaginationQuery$variables } from './__generated__/TriggersLinesPaginationQuery.graphql';
import { TriggerLineComponent, TriggerLineDummy } from './TriggerLine';

const nbOfRowsToLoad = 50;

interface TriggerLinesProps {
  queryRef: PreloadedQuery<TriggersLinesPaginationQuery>;
  dataColumns: DataColumns;
  paginationOptions?: TriggersLinesPaginationQuery$variables;
  setNumberOfElements?: UseLocalStorageHelpers['handleSetNumberOfElements'];
  onLabelClick?: (
    k: string,
    id: string,
    value: Record<string, unknown>,
    event: React.KeyboardEvent
  ) => void;
  containerRef?: MutableRefObject<GridTypeMap | null>;
  adminByPass?: boolean
}

export const triggersLinesQuery = graphql`
  query TriggersLinesPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: TriggersOrdering
    $orderMode: OrderingMode
    $filters: [TriggersFiltering!]
  ) {
    ...TriggersLines_data
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

const triggersLinesFragment = graphql`
  fragment TriggersLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "TriggersOrdering", defaultValue: name }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    filters: { type: "[TriggersFiltering!]" }
  )
  @refetchable(queryName: "TriggersLinesRefetchQuery") {
    triggersKnowledge(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_triggersKnowledge") {
      edges {
        node {
          id
          name
          description
          ...TriggerLine_node
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

const TriggersLines: FunctionComponent<TriggerLinesProps> = ({
  setNumberOfElements,
  queryRef,
  dataColumns,
  paginationOptions,
  onLabelClick,
  adminByPass = false,
  containerRef,
}) => {
  const { data, hasMore, loadMore, isLoadingMore } = usePreloadedPaginationFragment<
  TriggersLinesPaginationQuery,
  TriggersLines_data$key
  >({
    linesQuery: triggersLinesQuery,
    linesFragment: triggersLinesFragment,
    queryRef,
    nodePath: ['triggersKnowledge', 'pageInfo', 'globalCount'],
    setNumberOfElements,
  });
  return (
    <ListLinesContent
      initialLoading={!data}
      isLoading={isLoadingMore}
      loadMore={loadMore}
      hasMore={hasMore}
      dataList={data?.triggersKnowledge?.edges ?? []}
      globalCount={data?.triggersKnowledge?.pageInfo?.globalCount ?? nbOfRowsToLoad}
      LineComponent={TriggerLineComponent}
      DummyLineComponent={TriggerLineDummy}
      dataColumns={dataColumns}
      nbOfRowsToLoad={nbOfRowsToLoad}
      paginationOptions={paginationOptions}
      onLabelClick={onLabelClick}
      containerRef={containerRef}
      adminByPass={adminByPass}
    />
  );
};

export default TriggersLines;
