import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery } from 'react-relay';
import { DraftEntitiesLine_node$data } from '@components/drafts/__generated__/DraftEntitiesLine_node.graphql';
import { DraftEntitiesLinesPaginationQuery, DraftEntitiesLinesPaginationQuery$variables } from '@components/drafts/__generated__/DraftEntitiesLinesPaginationQuery.graphql';
import { DraftEntitiesLines_data$key } from '@components/drafts/__generated__/DraftEntitiesLines_data.graphql';
import { DraftEntitiesLine, DraftEntitiesLineDummy } from '@components/drafts/DraftEntitiesLine';
import usePreloadedPaginationFragment from '../../../utils/hooks/usePreloadedPaginationFragment';
import ListLinesContent from '../../../components/list_lines/ListLinesContent';
import { HandleAddFilter, UseLocalStorageHelpers } from '../../../utils/hooks/useLocalStorage';
import { DataColumns } from '../../../components/list_lines';

const nbOfRowsToLoad = 50;

interface DraftEntitiesLinesProps {
  setNumberOfElements: UseLocalStorageHelpers['handleSetNumberOfElements'];
  dataColumns: DataColumns;
  paginationOptions: DraftEntitiesLinesPaginationQuery$variables;
  queryRef: PreloadedQuery<DraftEntitiesLinesPaginationQuery>;
  selectedElements: Record<string, DraftEntitiesLine_node$data>;
  deSelectedElements: Record<string, DraftEntitiesLine_node$data>;
  onToggleEntity: (
    entity: DraftEntitiesLine_node$data,
    event: React.SyntheticEvent
  ) => void;
  selectAll: boolean;
  onLabelClick?: HandleAddFilter;
  redirectionMode?: string;
}

export const draftEntitiesLinesQuery = graphql`
    query DraftEntitiesLinesPaginationQuery(
        $types: [String]
        $search: String
        $count: Int!
        $cursor: ID
        $orderBy: StixDomainObjectsOrdering
        $orderMode: OrderingMode
        $filters: FilterGroup
    ) {
        ...DraftEntitiesLines_data
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

export const draftEntitiesLinesFragment = graphql`
    fragment DraftEntitiesLines_data on Query
    @argumentDefinitions(
        types: { type: "[String]" }
        search: { type: "String" }
        count: { type: "Int", defaultValue: 25 }
        cursor: { type: "ID" }
        orderBy: { type: "StixDomainObjectsOrdering", defaultValue: name }
        orderMode: { type: "OrderingMode", defaultValue: asc }
        filters: { type: "FilterGroup" }
    )
    @refetchable(queryName: "DraftEntitiesLinesRefetchQuery") {
        draftWorkspaceEntities(
            types: $types
            search: $search
            first: $count
            after: $cursor
            orderBy: $orderBy
            orderMode: $orderMode
            filters: $filters
        ) @connection(key: "Pagination_draftWorkspaceEntities") {
            edges {
                node {
                    ...DraftEntitiesLine_node
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

const DraftEntitiesLines: FunctionComponent<DraftEntitiesLinesProps> = ({
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
    DraftEntitiesLinesPaginationQuery,
    DraftEntitiesLines_data$key
  >({
    linesQuery: draftEntitiesLinesQuery,
    linesFragment: draftEntitiesLinesFragment,
    queryRef,
    nodePath: ['draftWorkspaceEntities', 'pageInfo', 'globalCount'],
    setNumberOfElements,
  });
  return (
    <ListLinesContent
      initialLoading={!data}
      loadMore={loadMore}
      hasMore={hasMore}
      isLoading={isLoadingMore}
      dataList={data?.draftWorkspaceEntities?.edges ?? []}
      globalCount={
        data?.draftWorkspaceEntities?.pageInfo?.globalCount ?? nbOfRowsToLoad
      }
      LineComponent={DraftEntitiesLine}
      DummyLineComponent={DraftEntitiesLineDummy}
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

export default DraftEntitiesLines;
