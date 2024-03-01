import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery } from 'react-relay';
import { DataColumns } from '../../../../components/list_lines';
import { UseLocalStorageHelpers } from '../../../../utils/hooks/useLocalStorage';
import usePreloadedPaginationFragment from '../../../../utils/hooks/usePreloadedPaginationFragment';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { ThreatActorIndividualLine, ThreatActorIndividualLineDummy } from './ThreatActorIndividualLine';
import {
  ThreatActorsIndividualLinesPaginationQuery,
  ThreatActorsIndividualLinesPaginationQuery$variables,
} from './__generated__/ThreatActorsIndividualLinesPaginationQuery.graphql';
import { ThreatActorsIndividualLines_data$key } from './__generated__/ThreatActorsIndividualLines_data.graphql';
import { ThreatActorIndividualLine_node$data } from './__generated__/ThreatActorIndividualLine_node.graphql';

const nbOfRowsToLoad = 50;

interface ThreatActorsIndividualLinesProps {
  dataColumns: DataColumns;
  setNumberOfElements: UseLocalStorageHelpers['handleSetNumberOfElements'];
  selectedElements: Record<string, ThreatActorIndividualLine_node$data>;
  deSelectedElements: Record<string, ThreatActorIndividualLine_node$data>;
  onToggleEntity: (
    entity: ThreatActorIndividualLine_node$data,
    event: React.SyntheticEvent,
  ) => void;
  selectAll: boolean;
  paginationOptions: ThreatActorsIndividualLinesPaginationQuery$variables;
  queryRef: PreloadedQuery<ThreatActorsIndividualLinesPaginationQuery>;
}

export const threatActorsIndividualLinesQuery = graphql`
  query ThreatActorsIndividualLinesPaginationQuery(
    $search: String
    $count: Int
    $cursor: ID
    $orderBy: ThreatActorsIndividualOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...ThreatActorsIndividualLines_data
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

const threatActorsIndividualLinesFragment = graphql`
  fragment ThreatActorsIndividualLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "ThreatActorsIndividualOrdering", defaultValue: name }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "ThreatActorsIndividualLinesRefetchQuery") {
    threatActorsIndividuals(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_threatActorsIndividuals") {
      edges {
        node {
          id
          name
          description
          ...ThreatActorIndividualLine_node
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

const ThreatActorsIndividualLines: FunctionComponent<
ThreatActorsIndividualLinesProps
> = ({
  dataColumns,
  selectedElements,
  deSelectedElements,
  selectAll,
  onToggleEntity,
  paginationOptions,
  queryRef,
  setNumberOfElements,
}) => {
  const { data, hasMore, loadMore, isLoadingMore } = usePreloadedPaginationFragment<
  ThreatActorsIndividualLinesPaginationQuery,
  ThreatActorsIndividualLines_data$key
  >({
    linesQuery: threatActorsIndividualLinesQuery,
    linesFragment: threatActorsIndividualLinesFragment,
    queryRef,
    nodePath: ['threatActorsIndividuals', 'pageInfo', 'globalCount'],
    setNumberOfElements,
  });

  return (
    <ListLinesContent
      hasMore={hasMore}
      initialLoading={!data}
      isLoading={isLoadingMore}
      loadMore={loadMore}
      dataList={data?.threatActorsIndividuals?.edges ?? []}
      globalCount={
        data?.threatActorsIndividuals?.pageInfo?.globalCount ?? nbOfRowsToLoad
      }
      LineComponent={ThreatActorIndividualLine}
      DummyLineComponent={ThreatActorIndividualLineDummy}
      dataColumns={dataColumns}
      nbOfRowsToLoad={nbOfRowsToLoad}
      paginationOptions={paginationOptions}
      selectedElements={selectedElements}
      deSelectedElements={deSelectedElements}
      onToggleEntity={onToggleEntity}
      selectAll={selectAll}
    />
  );
};

export default ThreatActorsIndividualLines;
