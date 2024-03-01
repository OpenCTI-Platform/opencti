import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery } from 'react-relay';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { InfrastructureLine, InfrastructureLineDummy } from './InfrastructureLine';
import { DataColumns } from '../../../../components/list_lines';
import { HandleAddFilter, UseLocalStorageHelpers } from '../../../../utils/hooks/useLocalStorage';
import usePreloadedPaginationFragment from '../../../../utils/hooks/usePreloadedPaginationFragment';
import { InfrastructuresLinesPaginationQuery, InfrastructuresLinesPaginationQuery$variables } from './__generated__/InfrastructuresLinesPaginationQuery.graphql';
import { InfrastructureLine_node$data } from './__generated__/InfrastructureLine_node.graphql';
import { InfrastructuresLines_data$key } from './__generated__/InfrastructuresLines_data.graphql';

const nbOfRowsToLoad = 50;

interface InfrastructuresLinesProps {
  paginationOptions?: InfrastructuresLinesPaginationQuery$variables;
  dataColumns: DataColumns;
  queryRef: PreloadedQuery<InfrastructuresLinesPaginationQuery>;
  setNumberOfElements: UseLocalStorageHelpers['handleSetNumberOfElements'];
  selectedElements: Record<string, InfrastructureLine_node$data>;
  deSelectedElements: Record<string, InfrastructureLine_node$data>;
  onToggleEntity: (
    entity: InfrastructureLine_node$data,
    event: React.SyntheticEvent
  ) => void;
  selectAll: boolean;
  onLabelClick?: HandleAddFilter;
}

export const infrastructuresLinesQuery = graphql`
  query InfrastructuresLinesPaginationQuery(
    $search: String
    $count: Int
    $cursor: ID
    $orderBy: InfrastructuresOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...InfrastructuresLines_data
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

const infrastructuresLinesFragment = graphql`
  fragment InfrastructuresLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int" }
    cursor: { type: "ID" }
    orderBy: { type: "InfrastructuresOrdering" }
    orderMode: { type: "OrderingMode", defaultValue: desc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "InfrastructuresLinesRefetchQuery") {
    infrastructures(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_infrastructures") {
      edges {
        node {
          id
          ...InfrastructureLine_node
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

const InfrastructuresLines: FunctionComponent<InfrastructuresLinesProps> = ({
  setNumberOfElements,
  dataColumns,
  queryRef,
  paginationOptions,
  selectedElements,
  deSelectedElements,
  selectAll,
  onToggleEntity,
  onLabelClick,
}) => {
  const { data, hasMore, loadMore, isLoadingMore } = usePreloadedPaginationFragment<
  InfrastructuresLinesPaginationQuery,
  InfrastructuresLines_data$key
  >({
    linesQuery: infrastructuresLinesQuery,
    linesFragment: infrastructuresLinesFragment,
    queryRef,
    nodePath: ['infrastructures', 'pageInfo', 'globalCount'],
    setNumberOfElements,
  });
  return (
    <ListLinesContent
      initialLoading={!data}
      hasMore={hasMore}
      loadMore={loadMore}
      isLoading={isLoadingMore}
      dataList={data?.infrastructures?.edges ?? []}
      globalCount={data?.infrastructures?.pageInfo?.globalCount ?? nbOfRowsToLoad}
      LineComponent={InfrastructureLine}
      DummyLineComponent={InfrastructureLineDummy}
      dataColumns={dataColumns}
      onLabelClick={onLabelClick}
      nbOfRowsToLoad={nbOfRowsToLoad}
      paginationOptions={paginationOptions}
      selectedElements={selectedElements}
      deSelectedElements={deSelectedElements}
      onToggleEntity={onToggleEntity}
      selectAll={selectAll}
    />
  );
};

export default InfrastructuresLines;
