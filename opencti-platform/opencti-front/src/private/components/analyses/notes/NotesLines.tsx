import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery } from 'react-relay';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { NoteLine, NoteLineDummy } from './NoteLine';
import { HandleAddFilter, UseLocalStorageHelpers } from '../../../../utils/hooks/useLocalStorage';
import { DataColumns } from '../../../../components/list_lines';
import usePreloadedPaginationFragment from '../../../../utils/hooks/usePreloadedPaginationFragment';
import { NotesLinesPaginationQuery, NotesLinesPaginationQuery$variables } from './__generated__/NotesLinesPaginationQuery.graphql';
import { NoteLine_node$data } from './__generated__/NoteLine_node.graphql';
import { NotesLines_data$key } from './__generated__/NotesLines_data.graphql';

const nbOfRowsToLoad = 50;

export const notesLinesQuery = graphql`
  query NotesLinesPaginationQuery(
    $search: String
    $count: Int
    $cursor: ID
    $orderBy: NotesOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...NotesLines_data
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

const notesLineFragment = graphql`
  fragment NotesLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "NotesOrdering", defaultValue: created }
    orderMode: { type: "OrderingMode", defaultValue: desc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "NotesLinesRefetchQuery") {
    notes(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_notes") {
      edges {
        node {
          id
          attribute_abstract
          content
          created
          createdBy {
            ... on Identity {
              id
              name
              entity_type
            }
          }
          objectMarking {
            id
            definition_type
            definition
            x_opencti_order
            x_opencti_color
          }
          ...NoteLine_node
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

interface NotesLinesProps {
  setNumberOfElements: UseLocalStorageHelpers['handleSetNumberOfElements'];
  dataColumns: DataColumns;
  paginationOptions: NotesLinesPaginationQuery$variables;
  queryRef: PreloadedQuery<NotesLinesPaginationQuery>;
  selectedElements: Record<string, NoteLine_node$data>;
  deSelectedElements: Record<string, NoteLine_node$data>;
  onToggleEntity: (
    entity: NoteLine_node$data,
    event: React.SyntheticEvent
  ) => void;
  selectAll: boolean;
  onLabelClick?: HandleAddFilter;
  redirectionMode?: string;
}

const NotesLines: FunctionComponent<NotesLinesProps> = ({
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
  NotesLinesPaginationQuery,
  NotesLines_data$key
  >({
    linesQuery: notesLinesQuery,
    linesFragment: notesLineFragment,
    queryRef,
    nodePath: ['notes', 'pageInfo', 'globalCount'],
    setNumberOfElements,
  });
  return (
    <ListLinesContent
      initialLoading={!data}
      loadMore={loadMore}
      hasMore={hasMore}
      isLoading={isLoadingMore}
      dataList={data?.notes?.edges ?? []}
      globalCount={data?.notes?.pageInfo?.globalCount ?? nbOfRowsToLoad}
      LineComponent={NoteLine}
      DummyLineComponent={NoteLineDummy}
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
export default NotesLines;
