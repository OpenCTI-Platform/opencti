import React from 'react';
import CourseOfActionCreation from '@components/techniques/courses_of_action/CourseOfActionCreation';
import { graphql } from 'react-relay';
import { CoursesOfActionLines_data$data } from '@components/techniques/__generated__/CoursesOfActionLines_data.graphql';
import {
  CoursesOfActionLinesPaginationQuery,
  CoursesOfActionLinesPaginationQuery$variables,
} from '@components/techniques/__generated__/CoursesOfActionLinesPaginationQuery.graphql';
import Security from '../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { useBuildEntityTypeBasedFilterContext, emptyFilterGroup } from '../../../utils/filters/filtersUtils';
import { useFormatter } from '../../../components/i18n';
import Breadcrumbs from '../../../components/Breadcrumbs';
import DataTable from '../../../components/dataGrid/DataTable';
import { UsePreloadedPaginationFragment } from '../../../utils/hooks/usePreloadedPaginationFragment';
import useHelper from '../../../utils/hooks/useHelper';

const LOCAL_STORAGE_KEY = 'coursesOfAction';

const CourseOfActionLineFragment = graphql`
  fragment CoursesOfActionLine_node on CourseOfAction {
    id
    entity_type
    name
    created
    modified
    objectMarking {
      id
      definition_type
      definition
      x_opencti_order
      x_opencti_color
    }
    objectLabel {
      id
      value
      color
    }
  }
`;

const coursesOfActionLinesQuery = graphql`
  query CoursesOfActionLinesPaginationQuery(
    $search: String
    $count: Int!
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
          ...CoursesOfActionLine_node
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

const CoursesOfAction = () => {
  const { t_i18n } = useFormatter();
  const { isFeatureEnable } = useHelper();
  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');
  const initialValues = {
    searchTerm: '',
    sortBy: 'name',
    orderAsc: true,
    openExports: false,
    filters: emptyFilterGroup,
  };
  const { viewStorage: { filters }, helpers: storageHelpers, paginationOptions } = usePaginationLocalStorage<CoursesOfActionLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    initialValues,
  );

  const contextFilters = useBuildEntityTypeBasedFilterContext('Course-Of-Action', filters);

  const queryPaginationOptions = {
    ...paginationOptions,
    filters: contextFilters,
  } as unknown as CoursesOfActionLinesPaginationQuery$variables;

  const dataColumns = {
    name: { percentWidth: 45 },
    objectLabel: { percentWidth: 25 },
    created: {},
    modified: {},
  };
  const queryRef = useQueryLoading<CoursesOfActionLinesPaginationQuery>(
    coursesOfActionLinesQuery,
    queryPaginationOptions,
  );

  const preloadedPaginationOptions = {
    linesQuery: coursesOfActionLinesQuery,
    linesFragment: coursesOfActionLinesFragment,
    queryRef,
    nodePath: ['coursesOfAction', 'pageInfo', 'globalCount'],
    setNumberOfElements: storageHelpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<CoursesOfActionLinesPaginationQuery>;

  return (
    <>
      <Breadcrumbs variant="list" elements={[{ label: t_i18n('Techniques') }, { label: t_i18n('Courses of action'), current: true }]} />
      {queryRef && (
        <DataTable
          dataColumns={dataColumns}
          preloadedPaginationProps={preloadedPaginationOptions}
          initialValues={initialValues}
          toolbarFilters={contextFilters}
          exportContext={{ entity_type: 'Course-Of-Action' }}
          lineFragment={CourseOfActionLineFragment}
          resolvePath={(data: CoursesOfActionLines_data$data) => data.coursesOfAction?.edges?.map((n) => n?.node)}
          storageKey={LOCAL_STORAGE_KEY}
          createButton={isFABReplaced && (
            <Security needs={[KNOWLEDGE_KNUPDATE]}>
              <CourseOfActionCreation paginationOptions={paginationOptions} />
            </Security>
          )}
        />
      )}
      {!isFABReplaced && (
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <CourseOfActionCreation paginationOptions={paginationOptions} />
        </Security>
      )}
    </>
  );
};

export default CoursesOfAction;
