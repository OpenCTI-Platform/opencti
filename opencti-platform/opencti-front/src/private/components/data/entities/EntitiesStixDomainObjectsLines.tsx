import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery } from 'react-relay';
import {
  EntitiesStixDomainObjectsLinesPaginationQuery,
  EntitiesStixDomainObjectsLinesPaginationQuery$variables,
} from '@components/data/entities/__generated__/EntitiesStixDomainObjectsLinesPaginationQuery.graphql';
import { EntitiesStixDomainObjectsLines_data$key } from '@components/data/entities/__generated__/EntitiesStixDomainObjectsLines_data.graphql';
import { EntitiesStixDomainObjectLine_node$data } from '@components/data/entities/__generated__/EntitiesStixDomainObjectLine_node.graphql';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { EntitiesStixDomainObjectLine, EntitiesStixDomainObjectLineDummy } from './EntitiesStixDomainObjectLine';
import usePreloadedPaginationFragment from '../../../../utils/hooks/usePreloadedPaginationFragment';
import { HandleAddFilter, UseLocalStorageHelpers } from '../../../../utils/hooks/useLocalStorage';
import { DataColumns } from '../../../../components/list_lines';

const nbOfRowsToLoad = 50;

interface EntitiesStixDomainObjectsLinesProps {
  setNumberOfElements: UseLocalStorageHelpers['handleSetNumberOfElements'];
  dataColumns: DataColumns;
  paginationOptions: EntitiesStixDomainObjectsLinesPaginationQuery$variables;
  queryRef: PreloadedQuery<EntitiesStixDomainObjectsLinesPaginationQuery>;
  selectedElements: Record<string, EntitiesStixDomainObjectLine_node$data>;
  deSelectedElements: Record<string, EntitiesStixDomainObjectLine_node$data>;
  onToggleEntity: (
    entity: EntitiesStixDomainObjectLine_node$data,
    event: React.SyntheticEvent
  ) => void;
  selectAll: boolean;
  onLabelClick?: HandleAddFilter;
  redirectionMode?: string;
}

export const entitiesStixDomainObjectsLinesQuery = graphql`
  query EntitiesStixDomainObjectsLinesPaginationQuery(
    $types: [String]
    $search: String
    $count: Int
    $cursor: ID
    $orderBy: StixDomainObjectsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...EntitiesStixDomainObjectsLines_data
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

export const entitiesStixDomainObjectsLinesFragment = graphql`
  fragment EntitiesStixDomainObjectsLines_data on Query
  @argumentDefinitions(
    types: { type: "[String]" }
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "StixDomainObjectsOrdering", defaultValue: name }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "EntitiesStixDomainObjectsLinesRefetchQuery") {
    stixDomainObjects(
      types: $types
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_stixDomainObjects") {
      edges {
        node {
          id
          entity_type
          created_at
          createdBy {
            ... on Identity {
              name
            }
          }
          objectMarking {
            id
            definition
            x_opencti_order
            x_opencti_color
          }
          ...EntitiesStixDomainObjectLine_node
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

const EntitiesStixDomainObjectsLines: FunctionComponent<EntitiesStixDomainObjectsLinesProps> = ({
  dataColumns,
  onLabelClick,
  onToggleEntity,
  selectedElements,
  deSelectedElements,
  selectAll,
  paginationOptions,
  setNumberOfElements,
  queryRef,
}) => {
  const { data, hasMore, loadMore, isLoadingMore } = usePreloadedPaginationFragment<
  EntitiesStixDomainObjectsLinesPaginationQuery,
  EntitiesStixDomainObjectsLines_data$key
  >({
    linesQuery: entitiesStixDomainObjectsLinesQuery,
    linesFragment: entitiesStixDomainObjectsLinesFragment,
    queryRef,
    nodePath: ['stixDomainObjects', 'pageInfo', 'globalCount'],
    setNumberOfElements,
  });
  return (
    <ListLinesContent
      initialLoading={!data}
      loadMore={loadMore}
      hasMore={hasMore}
      isLoading={isLoadingMore}
      dataList={data?.stixDomainObjects?.edges ?? []}
      globalCount={
        data?.stixDomainObjects?.pageInfo?.globalCount ?? nbOfRowsToLoad
      }
      LineComponent={EntitiesStixDomainObjectLine}
      DummyLineComponent={EntitiesStixDomainObjectLineDummy}
      dataColumns={dataColumns}
      nbOfRowsToLoad={nbOfRowsToLoad}
      onLabelClick={onLabelClick}
      selectedElements={selectedElements}
      deSelectedElements={deSelectedElements}
      selectAll={selectAll}
      onToggleEntity={onToggleEntity}
      paginationOptions={paginationOptions}
    />
  );
};

export default EntitiesStixDomainObjectsLines;
