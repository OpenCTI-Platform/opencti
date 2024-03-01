import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery } from 'react-relay';
import {
  CoursesOfActionLinesPaginationQuery,
  CoursesOfActionLinesPaginationQuery$variables,
} from '@components/techniques/courses_of_action/__generated__/CoursesOfActionLinesPaginationQuery.graphql';
import { CoursesOfActionLines_data$key } from '@components/techniques/courses_of_action/__generated__/CoursesOfActionLines_data.graphql';
import ListLinesContent from '../../../../components/list_lines/ListLinesContent';
import { CourseOfActionLine, CourseOfActionLineDummy } from './CourseOfActionLine';
import { DataColumns } from '../../../../components/list_lines';
import { HandleAddFilter, UseLocalStorageHelpers } from '../../../../utils/hooks/useLocalStorage';
import usePreloadedPaginationFragment from '../../../../utils/hooks/usePreloadedPaginationFragment';

const nbOfRowsToLoad = 50;

interface CoursesOfActionLinesProps {
  queryRef: PreloadedQuery<CoursesOfActionLinesPaginationQuery>;
  dataColumns: DataColumns;
  paginationOptions?: CoursesOfActionLinesPaginationQuery$variables;
  setNumberOfElements: UseLocalStorageHelpers['handleSetNumberOfElements'];
  onLabelClick: HandleAddFilter;
}

export const coursesOfActionLinesQuery = graphql`
  query CoursesOfActionLinesPaginationQuery(
    $search: String
    $count: Int
    $cursor: ID
    $orderBy: CoursesOfActionOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...CoursesOfActionLines_data
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

export const coursesOfActionLinesFragment = graphql`
  fragment CoursesOfActionLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "CoursesOfActionOrdering", defaultValue: name }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "CoursesOfActionLinesRefetchQuery") {
    coursesOfAction(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_coursesOfAction") {
      edges {
        node {
          name
          ...CourseOfActionLine_node
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

const CoursesOfActionLines: FunctionComponent<CoursesOfActionLinesProps> = ({
  setNumberOfElements,
  queryRef,
  dataColumns,
  paginationOptions,
  onLabelClick,
}) => {
  const { data, hasMore, loadMore, isLoadingMore } = usePreloadedPaginationFragment<
  CoursesOfActionLinesPaginationQuery,
  CoursesOfActionLines_data$key
  >({
    linesQuery: coursesOfActionLinesQuery,
    linesFragment: coursesOfActionLinesFragment,
    queryRef,
    nodePath: ['coursesOfAction', 'pageInfo', 'globalCount'],
    setNumberOfElements,
  });

  return (
    <ListLinesContent
      initialLoading={!data}
      loadMore={loadMore}
      hasMore={hasMore}
      isLoading={isLoadingMore}
      dataList={data?.coursesOfAction?.edges ?? []}
      globalCount={
        data?.coursesOfAction?.pageInfo?.globalCount ?? nbOfRowsToLoad
      }
      LineComponent={CourseOfActionLine}
      DummyLineComponent={CourseOfActionLineDummy}
      dataColumns={dataColumns}
      nbOfRowsToLoad={nbOfRowsToLoad}
      paginationOptions={paginationOptions}
      onLabelClick={onLabelClick}
    />
  );
};

export default CoursesOfActionLines;
