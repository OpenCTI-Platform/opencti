import React, { FunctionComponent, useState, useEffect } from 'react';
import { graphql, fetchQuery } from 'react-relay';
import { environment } from '../../../relay/environment';
import { ReportsLinesPaginationQuery, ReportsLinesPaginationQuery$variables } from '@components/analyses/__generated__/ReportsLinesPaginationQuery.graphql';
import { ReportsLines_data$data } from '@components/analyses/__generated__/ReportsLines_data.graphql';
import IconButton from '@mui/material/IconButton';
import Tooltip from '@mui/material/Tooltip';
import { Assignment } from '@mui/icons-material';
import ReportCreation from './reports/ReportCreation';
import Security from '../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';
import useAuth from '../../../utils/hooks/useAuth';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { emptyFilterGroup, useBuildEntityTypeBasedFilterContext } from '../../../utils/filters/filtersUtils';
import { useFormatter } from '../../../components/i18n';
import DataTable from '../../../components/dataGrid/DataTable';
import { UsePreloadedPaginationFragment } from '../../../utils/hooks/usePreloadedPaginationFragment';
import { DataTableProps } from '../../../components/dataGrid/dataTableTypes';
import Breadcrumbs from '../../../components/Breadcrumbs';
import useConnectedDocumentModifier from '../../../utils/hooks/useConnectedDocumentModifier';
import StixDomainObjectFormSelector from '../common/stix_domain_objects/StixDomainObjectFormSelector';

const reportLineFragment = graphql`
  fragment ReportsLine_node on Report {
    id
    entity_type
    name
    description
    published
    report_types
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
        id
        name
        color
      }
    }
    workflowEnabled
    created_at
  }
`;

const reportsLinesQuery = graphql`
  query ReportsLinesPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: ReportsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...ReportsLines_data
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

const reportsLineFragment = graphql`
  fragment ReportsLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "ReportsOrdering", defaultValue: name }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "ReportsLinesRefetchQuery") {
    reports(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_reports") {
      edges {
        node {
          id
          name
          published
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
          ...ReportsLine_node
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

const LOCAL_STORAGE_KEY = 'reports';

const checkFormsQuery = graphql`
  query ReportsCheckFormsQuery {
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

const Reports: FunctionComponent = () => {
  const { t_i18n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Reports | Analyses'));
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
              return formEntityType.toLowerCase() === 'report';
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
    filters: emptyFilterGroup,
    searchTerm: '',
    sortBy: 'published',
    orderAsc: false,
    openExports: false,
    redirectionMode: 'overview',
  };
  const {
    viewStorage,
    paginationOptions,
    helpers: storageHelpers,
  } = usePaginationLocalStorage<ReportsLinesPaginationQuery$variables>(LOCAL_STORAGE_KEY, initialValues);
  const {
    filters,
  } = viewStorage;

  const contextFilters = useBuildEntityTypeBasedFilterContext('Report', filters);
  const queryPaginationOptions = {
    ...paginationOptions,
    filters: contextFilters,
  } as unknown as ReportsLinesPaginationQuery$variables;
  const queryRef = useQueryLoading<ReportsLinesPaginationQuery>(
    reportsLinesQuery,
    queryPaginationOptions,
  );

  const preloadedPaginationProps = {
    linesQuery: reportsLinesQuery,
    linesFragment: reportsLineFragment,
    queryRef,
    nodePath: ['reports', 'pageInfo', 'globalCount'],
    setNumberOfElements: storageHelpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<ReportsLinesPaginationQuery>;

  const isRuntimeSort = isRuntimeFieldEnable() ?? false;
  const dataColumns: DataTableProps['dataColumns'] = {
    name: {
      percentWidth: 25,
      isSortable: true,
    },
    report_types: {},
    createdBy: {
      percentWidth: 12,
      isSortable: isRuntimeSort,
    },
    creator: {
      percentWidth: 12,
      isSortable: isRuntimeSort,
    },
    objectLabel: { percentWidth: 15 },
    published: {},
    x_opencti_workflow_id: { percentWidth: 8 },
    objectMarking: {
      isSortable: isRuntimeSort,
      percentWidth: 8,
    },
  };
  return (
    <span data-testid="report-page">
      <Breadcrumbs elements={[{ label: t_i18n('Analyses') }, { label: t_i18n('Reports'), current: true }]} />
      {queryRef && (
        <DataTable
          dataColumns={dataColumns}
          resolvePath={(data: ReportsLines_data$data) => data.reports?.edges?.map((n) => n?.node)}
          storageKey={LOCAL_STORAGE_KEY}
          initialValues={initialValues}
          toolbarFilters={contextFilters}
          preloadedPaginationProps={preloadedPaginationProps}
          lineFragment={reportLineFragment}
          exportContext={{ entity_type: 'Report' }}
          redirectionModeEnabled
          createButton={(
            <Security needs={[KNOWLEDGE_KNUPDATE]}>
              <div style={{ display: 'flex', marginLeft: 8 }}>
                {hasAvailableForms && (
                  <Tooltip title={t_i18n('Use a form to create a report')}>
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
                <ReportCreation paginationOptions={queryPaginationOptions} />
              </div>
            </Security>
          )}
        />
      )}
      <StixDomainObjectFormSelector
        open={isFormSelectorOpen}
        handleClose={() => setIsFormSelectorOpen(false)}
        entityType="Report"
      />
    </span>
  );
};

export default Reports;
