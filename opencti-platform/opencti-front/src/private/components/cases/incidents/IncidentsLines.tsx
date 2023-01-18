import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery } from 'react-relay';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { DataColumns } from '../../../../components/list_lines';
import type { UseLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import usePreloadedPaginationFragment from '../../../../utils/hooks/usePreloadedPaginationFragment';
import { IncidentLine, IncidentLineDummy } from './IncidentLine';
import {
  IncidentsLinesCasesPaginationQuery,
  IncidentsLinesCasesPaginationQuery$variables,
} from './__generated__/IncidentsLinesCasesPaginationQuery.graphql';
import { IncidentsLinesCases_data$key } from './__generated__/IncidentsLinesCases_data.graphql';
import { IncidentLineCase_node$data } from './__generated__/IncidentLineCase_node.graphql';

const nbOfRowsToLoad = 50;

interface CasesLinesProps {
  paginationOptions?: IncidentsLinesCasesPaginationQuery$variables;
  dataColumns: DataColumns;
  queryRef: PreloadedQuery<IncidentsLinesCasesPaginationQuery>;
  setNumberOfElements: UseLocalStorage[2]['handleSetNumberOfElements'];
  selectedElements: Record<string, IncidentLineCase_node$data>;
  deSelectedElements: Record<string, IncidentLineCase_node$data>;
  onToggleEntity: (
    entity: IncidentLineCase_node$data,
    event: React.SyntheticEvent
  ) => void;
  selectAll: boolean;
}

export const incidentsLinesQuery = graphql`
  query IncidentsLinesCasesPaginationQuery(
    $search: String
    $count: Int
    $cursor: ID
    $orderBy: CasesOrdering
    $orderMode: OrderingMode
    $filters: [CasesFiltering!]
  ) {
    ...IncidentsLinesCases_data
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

const incidentsLinesFragment = graphql`
  fragment IncidentsLinesCases_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int" }
    cursor: { type: "ID" }
    orderBy: { type: "CasesOrdering" }
    orderMode: { type: "OrderingMode", defaultValue: desc }
    filters: { type: "[CasesFiltering!]" }
  )
  @refetchable(queryName: "IncidentsCasesLinesRefetchQuery") {
    cases(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_incidents_cases") {
      edges {
        node {
          id
          ...IncidentLineCase_node
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

const IncidentsLines: FunctionComponent<CasesLinesProps> = ({
  setNumberOfElements,
  dataColumns,
  queryRef,
  paginationOptions,
  selectedElements,
  deSelectedElements,
  selectAll,
  onToggleEntity,
}) => {
  const { data, hasMore, loadMore, isLoadingMore } = usePreloadedPaginationFragment<
  IncidentsLinesCasesPaginationQuery,
  IncidentsLinesCases_data$key
  >({
    linesQuery: incidentsLinesQuery,
    linesFragment: incidentsLinesFragment,
    queryRef,
    nodePath: ['cases', 'pageInfo', 'globalCount'],
    setNumberOfElements,
  });
  return (
    <ListLinesContent
      initialLoading={!data}
      hasMore={hasMore}
      loadMore={loadMore}
      isLoading={isLoadingMore}
      dataList={data?.cases?.edges ?? []}
      globalCount={data?.cases?.pageInfo?.globalCount ?? nbOfRowsToLoad}
      LineComponent={IncidentLine}
      DummyLineComponent={IncidentLineDummy}
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

export default IncidentsLines;
