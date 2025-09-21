import React, { FunctionComponent, useState, useEffect } from 'react';
import { graphql, fetchQuery } from 'react-relay';
import { environment } from '../../../relay/environment';
import IconButton from '@mui/material/IconButton';
import Tooltip from '@mui/material/Tooltip';
import { Assignment } from '@mui/icons-material';
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
import StixDomainObjectFormSelector from '../common/stix_domain_objects/StixDomainObjectFormSelector';

const LOCAL_STORAGE_KEY = 'groupings';

const checkFormsQuery = graphql`
  query GroupingsCheckFormsQuery {
    forms(first: 50, orderBy: name, orderMode: asc) {
      edges {
        node {
          id
          active
          form_schema
        }
      }
    }
  }
`;

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
    draftVersion {
      draft_id
      draft_operation
    }
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
  const [isFormSelectorOpen, setIsFormSelectorOpen] = useState(false);
  const [hasAvailableForms, setHasAvailableForms] = useState(false);
  const {
    platformModuleHelpers: { isRuntimeFieldEnable },
  } = useAuth();

  useEffect(() => {
    fetchQuery(environment, checkFormsQuery, {}).toPromise()
      .then((data: any) => {
        if (data?.forms?.edges) {
          const hasForms = data.forms.edges.some(({ node }: any) => {
            if (!node.active) return false;
            try {
              const schema = JSON.parse(node.form_schema);
              const formEntityType = schema.mainEntityType || '';
              return formEntityType.toLowerCase() === 'grouping';
            } catch {
              return false;
            }
          });
          setHasAvailableForms(hasForms);
        }
      })
      .catch(() => setHasAvailableForms(false));
  }, []);

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
      <Breadcrumbs elements={[{ label: t_i18n('Analyses') }, { label: t_i18n('Groupings'), current: true }]} />
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
          createButton={(
            <Security needs={[KNOWLEDGE_KNUPDATE]}>
              <div style={{ display: 'flex', marginLeft: 8 }}>
                {hasAvailableForms && (
                  <Tooltip title={t_i18n('Use a form to create a grouping')}>
                    <IconButton
                      onClick={() => setIsFormSelectorOpen(true)}
                      color="primary"
                      size="medium"
                      style={{
                        border: '1px solid',
                        borderRadius: '4px',
                        padding: '6px',
                      }}
                    >
                      <Assignment />
                    </IconButton>
                  </Tooltip>
                )}
                <GroupingCreation paginationOptions={queryPaginationOptions} />
              </div>
            </Security>
          )}
        />
      )}
      <StixDomainObjectFormSelector
        open={isFormSelectorOpen}
        handleClose={() => setIsFormSelectorOpen(false)}
        entityType="Grouping"
      />
    </span>
  );
};

export default Groupings;
