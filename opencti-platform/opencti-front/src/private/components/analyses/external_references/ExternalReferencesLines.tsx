import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery } from 'react-relay';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { ExternalReferenceLine, ExternalReferenceLineDummy } from './ExternalReferenceLine';
import { ExternalReferencesLines_data$key } from './__generated__/ExternalReferencesLines_data.graphql';
import { ExternalReferencesLinesPaginationQuery, ExternalReferencesLinesPaginationQuery$variables } from './__generated__/ExternalReferencesLinesPaginationQuery.graphql';
import { ExternalReferenceLine_node$data } from './__generated__/ExternalReferenceLine_node.graphql';
import { UseLocalStorageHelpers } from '../../../../utils/hooks/useLocalStorage';
import usePreloadedPaginationFragment from '../../../../utils/hooks/usePreloadedPaginationFragment';
import { DataColumns } from '../../../../components/list_lines';

const nbOfRowsToLoad = 50;

interface ExternalReferencesLinesProps {
  setNumberOfElements: UseLocalStorageHelpers['handleSetNumberOfElements'];
  dataColumns: DataColumns;
  paginationOptions: ExternalReferencesLinesPaginationQuery$variables;
  queryRef: PreloadedQuery<ExternalReferencesLinesPaginationQuery>;
  selectedElements: Record<string, ExternalReferenceLine_node$data>;
  deSelectedElements: Record<string, ExternalReferenceLine_node$data>;
  onToggleEntity: (
    entity: ExternalReferenceLine_node$data,
    event: React.SyntheticEvent
  ) => void;
  selectAll: boolean;
}

export const externalReferencesLinesQuery = graphql`
  query ExternalReferencesLinesPaginationQuery(
    $search: String
    $count: Int
    $cursor: ID
    $orderBy: ExternalReferencesOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...ExternalReferencesLines_data
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

const externalReferencesLineFragment = graphql`
  fragment ExternalReferencesLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "ExternalReferencesOrdering", defaultValue: source_name }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "ExternalReferencesLinesRefetchQuery") {
    externalReferences(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_externalReferences") {
      edges {
        node {
          ...ExternalReferenceLine_node
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

const ExternalReferencesLines: FunctionComponent<
ExternalReferencesLinesProps
> = ({
  dataColumns,
  paginationOptions,
  queryRef,
  selectedElements,
  deSelectedElements,
  selectAll,
  onToggleEntity,
  setNumberOfElements,
}) => {
  const { data, hasMore, loadMore, isLoadingMore } = usePreloadedPaginationFragment<
  ExternalReferencesLinesPaginationQuery,
  ExternalReferencesLines_data$key
  >({
    linesQuery: externalReferencesLinesQuery,
    linesFragment: externalReferencesLineFragment,
    queryRef,
    nodePath: ['externalReferences', 'pageInfo', 'globalCount'],
    setNumberOfElements,
  });
  return (
    <ListLinesContent
      initialLoading={!data}
      hasMore={hasMore}
      loadMore={loadMore}
      isLoading={isLoadingMore}
      dataList={data?.externalReferences?.edges ?? []}
      globalCount={
        data?.externalReferences?.pageInfo?.globalCount ?? nbOfRowsToLoad
      }
      LineComponent={ExternalReferenceLine}
      DummyLineComponent={ExternalReferenceLineDummy}
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

export default ExternalReferencesLines;
