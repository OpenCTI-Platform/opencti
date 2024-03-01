import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery } from 'react-relay';
import { ArtifactsLinesPaginationQuery, ArtifactsLinesPaginationQuery$variables } from '@components/observations/artifacts/__generated__/ArtifactsLinesPaginationQuery.graphql';
import { ArtifactsLines_data$key } from '@components/observations/artifacts/__generated__/ArtifactsLines_data.graphql';
import { ArtifactLine_node$data } from '@components/observations/artifacts/__generated__/ArtifactLine_node.graphql';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { ArtifactLine, ArtifactLineDummy } from './ArtifactLine';
import { DataColumns } from '../../../../components/list_lines';
import { HandleAddFilter, UseLocalStorageHelpers } from '../../../../utils/hooks/useLocalStorage';
import usePreloadedPaginationFragment from '../../../../utils/hooks/usePreloadedPaginationFragment';

const nbOfRowsToLoad = 50;

interface ArtifactsLinesProps {
  queryRef: PreloadedQuery<ArtifactsLinesPaginationQuery>;
  dataColumns: DataColumns;
  paginationOptions?: ArtifactsLinesPaginationQuery$variables;
  setNumberOfElements: UseLocalStorageHelpers['handleSetNumberOfElements'];
  selectedElements: Record<string, ArtifactLine_node$data>;
  deSelectedElements: Record<string, ArtifactLine_node$data>;
  onToggleEntity: (
    entity: ArtifactLine_node$data,
    event: React.SyntheticEvent
  ) => void;
  selectAll: boolean;
  onLabelClick?: HandleAddFilter;
}

export const artifactsLinesQuery = graphql`
  query ArtifactsLinesPaginationQuery(
    $types: [String]
    $search: String
    $count: Int
    $cursor: ID
    $orderBy: StixCyberObservablesOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...ArtifactsLines_data
    @arguments(
      types: $types
      search: $search
      count: $count
      cursor: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    )
  }
`;

const artifactsLinesFragment = graphql`
  fragment ArtifactsLines_data on Query
  @argumentDefinitions(
    types: { type: "[String]" }
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: {
      type: "StixCyberObservablesOrdering"
      defaultValue: created_at
    }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "ArtifactsLinesRefetchQuery") {
    stixCyberObservables(
      types: $types
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_stixCyberObservables") {
      edges {
        node {
          id
          entity_type
          observable_value
          created_at
          objectMarking {
            id
            definition_type
            definition
            x_opencti_order
            x_opencti_color
          }
          ...ArtifactLine_node
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

const ArtifactsLines: FunctionComponent<ArtifactsLinesProps> = ({
  dataColumns,
  onLabelClick,
  onToggleEntity,
  selectedElements,
  deSelectedElements,
  selectAll,
  setNumberOfElements,
  queryRef,
  paginationOptions,
}) => {
  const { data, hasMore, loadMore, isLoadingMore } = usePreloadedPaginationFragment<
  ArtifactsLinesPaginationQuery,
  ArtifactsLines_data$key
  >({
    linesQuery: artifactsLinesQuery,
    linesFragment: artifactsLinesFragment,
    queryRef,
    nodePath: ['stixCyberObservables', 'pageInfo', 'globalCount'],
    setNumberOfElements,
  });
  return (
    <ListLinesContent
      initialLoading={!data}
      loadMore={loadMore}
      hasMore={hasMore}
      isLoading={isLoadingMore}
      dataList={data?.stixCyberObservables?.edges ?? []}
      globalCount={data?.stixCyberObservables?.pageInfo?.globalCount ?? nbOfRowsToLoad}
      LineComponent={ArtifactLine}
      DummyLineComponent={ArtifactLineDummy}
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

export default ArtifactsLines;
