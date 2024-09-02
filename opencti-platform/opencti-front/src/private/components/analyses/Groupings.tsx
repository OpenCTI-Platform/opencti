import React, { FunctionComponent } from 'react';
import useHelper from 'src/utils/hooks/useHelper';
import { graphql } from 'react-relay';
import { GroupingsLinesPaginationQuery, GroupingsLinesPaginationQuery$variables } from '@components/analyses/__generated__/GroupingsLinesPaginationQuery.graphql';
import { GroupingsLines_data$data } from '@components/analyses/__generated__/GroupingsLines_data.graphql';
import GroupingCreation from './groupings/GroupingCreation';
import Security from '../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';
import useAuth from '../../../utils/hooks/useAuth';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { emptyFilterGroup, useBuildEntityTypeBasedFilterContext, useGetDefaultFilterObject } from '../../../utils/filters/filtersUtils';
import { useFormatter } from '../../../components/i18n';
import Breadcrumbs from '../../../components/Breadcrumbs';
import useConnectedDocumentModifier from '../../../utils/hooks/useConnectedDocumentModifier';
import { DataTableProps } from '../../../components/dataGrid/dataTableTypes';
import DataTable from '../../../components/dataGrid/DataTable';
import { UsePreloadedPaginationFragment } from '../../../utils/hooks/usePreloadedPaginationFragment';

const LOCAL_STORAGE_KEY = 'groupings';

interface GroupingsProps {
  match: { params: { groupingContext: string } };
}

const groupingLineFragment = graphql`
  fragment GroupingsLine_node on Grouping {
    id
    entity_type
    created
    name
    description
    context
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
    objectLabel {
      id
      value
      color
    }
    creators {
      id
      name
    }
    status {
      id
      order
      template {
        name
        color
      }
    }
    workflowEnabled
  }
`;

const groupingsLinesQuery = graphql`
  query GroupingsLinesPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: GroupingsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...GroupingsLines_data
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

const groupingsLineFragment = graphql`
  fragment GroupingsLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "GroupingsOrdering", defaultValue: name }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "GroupingsLinesRefetchQuery") {
    groupings(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_groupings") {
      edges {
        node {
          id
          name
          context
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
          ...GroupingsLine_node
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

const Groupings: FunctionComponent<GroupingsProps> = () => {
  const { t_i18n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Groupings | Analyses'));
  const { isFeatureEnable } = useHelper();
  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');
  const {
    platformModuleHelpers: { isRuntimeFieldEnable },
  } = useAuth();

  const initialValues = {
    filters: {
      ...emptyFilterGroup,
      filters: useGetDefaultFilterObject(['context'], ['Grouping']),
    },
    searchTerm: '',
    sortBy: 'created',
    orderAsc: false,
    openExports: false,
    count: 25,
  };
  const {
    viewStorage,
    paginationOptions,
    helpers: storageHelpers,
  } = usePaginationLocalStorage<GroupingsLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    initialValues,
  );
  const {
    filters,
  } = viewStorage;

  const contextFilters = useBuildEntityTypeBasedFilterContext('Grouping', filters);
  const queryPaginationOptions = {
    ...paginationOptions,
    filters: contextFilters,
  } as unknown as GroupingsLinesPaginationQuery$variables;
  const queryRef = useQueryLoading<GroupingsLinesPaginationQuery>(
    groupingsLinesQuery,
    queryPaginationOptions,
  );

  const isRuntimeSort = isRuntimeFieldEnable() ?? false;
  const dataColumns: DataTableProps['dataColumns'] = {
    name: { percentWidth: 25 },
    context: {},
    createdBy: { isSortable: isRuntimeSort },
    creator: { isSortable: isRuntimeSort },
    objectLabel: {},
    created: { percentWidth: 10 },
    x_opencti_workflow_id: {},
    objectMarking: { isSortable: isRuntimeSort },
  };

  const preloadedPaginationProps = {
    linesQuery: groupingsLinesQuery,
    linesFragment: groupingsLineFragment,
    queryRef,
    nodePath: ['groupings', 'pageInfo', 'globalCount'],
    setNumberOfElements: storageHelpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<GroupingsLinesPaginationQuery>;

  return (
    <span data-testid="groupings-page">
      <Breadcrumbs variant="list" elements={[{ label: t_i18n('Analyses') }, { label: t_i18n('Groupings'), current: true }]} />
      {queryRef && (
        <DataTable
          dataColumns={dataColumns}
          resolvePath={(data: GroupingsLines_data$data) => data.groupings?.edges?.map((n) => n?.node)}
          storageKey={LOCAL_STORAGE_KEY}
          initialValues={initialValues}
          toolbarFilters={contextFilters}
          preloadedPaginationProps={preloadedPaginationProps}
          lineFragment={groupingLineFragment}
          exportContext={{ entity_type: 'Grouping' }}
          createButton={isFABReplaced && (
            <Security needs={[KNOWLEDGE_KNUPDATE]}>
              <GroupingCreation paginationOptions={queryPaginationOptions} />
            </Security>
          )}
        />
      )}
      {!isFABReplaced && (
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <GroupingCreation paginationOptions={queryPaginationOptions} />
        </Security>
      )}
    </span>
  );
};

export default Groupings;
