import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery } from 'react-relay';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { DataColumns } from '../../../../components/list_lines';
import { UseLocalStorageHelpers } from '../../../../utils/hooks/useLocalStorage';
import usePreloadedPaginationFragment from '../../../../utils/hooks/usePreloadedPaginationFragment';
import { CaseIncidentLine, CaseIncidentLineDummy } from './CaseIncidentLine';
import { CaseIncidentsLinesCases_data$key } from './__generated__/CaseIncidentsLinesCases_data.graphql';
import {
  CaseIncidentsLinesCasesPaginationQuery,
  CaseIncidentsLinesCasesPaginationQuery$variables,
} from './__generated__/CaseIncidentsLinesCasesPaginationQuery.graphql';
import { CaseIncidentLineCase_node$data } from './__generated__/CaseIncidentLineCase_node.graphql';

const nbOfRowsToLoad = 50;

interface CaseIncidentsLinesProps {
  paginationOptions?: CaseIncidentsLinesCasesPaginationQuery$variables;
  dataColumns: DataColumns;
  queryRef: PreloadedQuery<CaseIncidentsLinesCasesPaginationQuery>;
  setNumberOfElements: UseLocalStorageHelpers['handleSetNumberOfElements'];
  selectedElements: Record<string, CaseIncidentLineCase_node$data>;
  deSelectedElements: Record<string, CaseIncidentLineCase_node$data>;
  onToggleEntity: (
    entity: CaseIncidentLineCase_node$data,
    event: React.SyntheticEvent
  ) => void;
  selectAll: boolean;
}

export const caseIncidentsLinesQuery = graphql`
  query CaseIncidentsLinesCasesPaginationQuery(
    $search: String
    $count: Int
    $cursor: ID
    $orderBy: CaseIncidentsOrdering
    $orderMode: OrderingMode
    $filters: [CaseIncidentsFiltering!]
  ) {
    ...CaseIncidentsLinesCases_data
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

const caseIncidentsLinesFragment = graphql`
  fragment CaseIncidentsLinesCases_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int" }
    cursor: { type: "ID" }
    orderBy: { type: "CaseIncidentsOrdering" }
    orderMode: { type: "OrderingMode", defaultValue: desc }
    filters: { type: "[CaseIncidentsFiltering!]" }
  )
  @refetchable(queryName: "CaseIncidentsCasesLinesRefetchQuery") {
    caseIncidents(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_incidents_caseIncidents") {
      edges {
        node {
          id
          ...CaseIncidentLineCase_node
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

const CaseIncidentsLines: FunctionComponent<CaseIncidentsLinesProps> = ({
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
  CaseIncidentsLinesCasesPaginationQuery,
  CaseIncidentsLinesCases_data$key
  >({
    linesQuery: caseIncidentsLinesQuery,
    linesFragment: caseIncidentsLinesFragment,
    queryRef,
    nodePath: ['caseIncidents', 'pageInfo', 'globalCount'],
    setNumberOfElements,
  });
  return (
    <ListLinesContent
      initialLoading={!data}
      hasMore={hasMore}
      loadMore={loadMore}
      isLoading={isLoadingMore}
      dataList={data?.caseIncidents?.edges ?? []}
      globalCount={data?.caseIncidents?.pageInfo?.globalCount ?? nbOfRowsToLoad}
      LineComponent={CaseIncidentLine}
      DummyLineComponent={CaseIncidentLineDummy}
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

export default CaseIncidentsLines;
