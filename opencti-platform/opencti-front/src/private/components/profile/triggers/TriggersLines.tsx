import { GridTypeMap } from '@mui/material';
import React, { FunctionComponent, MutableRefObject } from 'react';
import { graphql, PreloadedQuery } from 'react-relay';
import { DataColumns } from '../../../../components/list_lines';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { HandleAddFilter, UseLocalStorageHelpers } from '../../../../utils/hooks/useLocalStorage';
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
  onLabelClick?: HandleAddFilter;
  containerRef?: MutableRefObject<GridTypeMap | null>;
  bypassEditionRestriction: boolean;
}

export const triggersLinesQuery = graphql`
  query TriggersLinesPaginationQuery(
    $search: String
    $count: Int
    $cursor: ID
    $orderBy: TriggersOrdering
    $orderMode: OrderingMode
    $includeAuthorities: Boolean
    $filters: FilterGroup
  ) {
    ...TriggersLines_data
    @arguments(
      search: $search
      count: $count
      cursor: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      includeAuthorities: $includeAuthorities
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
    includeAuthorities: { type: "Boolean", defaultValue: false }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "TriggersLinesRefetchQuery") {
    triggersKnowledge(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      includeAuthorities: $includeAuthorities
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
  containerRef,
  bypassEditionRestriction,
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
      bypassEditionRestriction={bypassEditionRestriction}
    />
  );
};

export default TriggersLines;
