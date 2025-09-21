import React, { FunctionComponent, useState, useEffect } from 'react';
import { graphql, fetchQuery } from 'react-relay';
import IconButton from '@mui/material/IconButton';
import Tooltip from '@mui/material/Tooltip';
import { Assignment } from '@mui/icons-material';
import {
  CaseIncidentsLinesCasesPaginationQuery,
  CaseIncidentsLinesCasesPaginationQuery$variables,
} from '@components/cases/__generated__/CaseIncidentsLinesCasesPaginationQuery.graphql';
import { CaseIncidentsLinesCases_data$data } from '@components/cases/__generated__/CaseIncidentsLinesCases_data.graphql';
import { environment } from '../../../relay/environment';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import useAuth from '../../../utils/hooks/useAuth';
import Security from '../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';
import CaseIncidentCreation from './case_incidents/CaseIncidentCreation';
import { emptyFilterGroup, useBuildEntityTypeBasedFilterContext } from '../../../utils/filters/filtersUtils';
import { useFormatter } from '../../../components/i18n';
import Breadcrumbs from '../../../components/Breadcrumbs';
import DataTable from '../../../components/dataGrid/DataTable';
import { DataTableProps } from '../../../components/dataGrid/dataTableTypes';
import { UsePreloadedPaginationFragment } from '../../../utils/hooks/usePreloadedPaginationFragment';
import useConnectedDocumentModifier from '../../../utils/hooks/useConnectedDocumentModifier';
import StixDomainObjectFormSelector from '../common/stix_domain_objects/StixDomainObjectFormSelector';

interface CaseIncidentsProps {
  inputValue?: string;
}

const caseIncidentFragment = graphql`
  fragment CaseIncidentsLineCase_node on CaseIncident {
    id
    name
    description
    rating
    priority
    severity
    created
    entity_type
    response_types
    draftVersion {
      draft_id
      draft_operation
    }
    objectAssignee {
      entity_type
      id
      name
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

const caseIncidentsLinesQuery = graphql`
  query CaseIncidentsLinesCasesPaginationQuery(
    $search: String
    $count: Int
    $cursor: ID
    $orderBy: CaseIncidentsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...CaseIncidentsLinesCases_data
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

const caseIncidentsLinesFragment = graphql`
  fragment CaseIncidentsLinesCases_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int" }
    cursor: { type: "ID" }
    orderBy: { type: "CaseIncidentsOrdering" }
    orderMode: { type: "OrderingMode", defaultValue: desc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "CaseIncidentsCasesLinesRefetchQuery") {
    caseIncidents(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_incidents_caseIncidents") {
      edges {
        node {
          id
          ...CaseIncidentsLineCase_node
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

export const LOCAL_STORAGE_KEY_CASE_INCIDENT = 'caseIncidents';

const checkFormsQuery = graphql`
  query CaseIncidentsCheckFormsQuery {
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

const CaseIncidents: FunctionComponent<CaseIncidentsProps> = () => {
  const { t_i18n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Incident Responses | Cases'));
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
              return formEntityType.toLowerCase() === 'case-incident' || formEntityType.toLowerCase() === 'case_incident';
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
    searchTerm: '',
    sortBy: 'created',
    orderAsc: false,
    openExports: false,
    filters: emptyFilterGroup,
  };
  const { viewStorage, helpers: storageHelpers, paginationOptions } = usePaginationLocalStorage<CaseIncidentsLinesCasesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY_CASE_INCIDENT,
    initialValues,
  );

  const {
    filters,
  } = viewStorage;

  const contextFilters = useBuildEntityTypeBasedFilterContext('Case-Incident', filters);
  const queryPaginationOptions = {
    ...paginationOptions,
    filters: contextFilters,
  } as unknown as CaseIncidentsLinesCasesPaginationQuery$variables;
  const queryRef = useQueryLoading<CaseIncidentsLinesCasesPaginationQuery>(
    caseIncidentsLinesQuery,
    queryPaginationOptions,
  );

  const isRuntimeSort = isRuntimeFieldEnable() ?? false;
  const dataColumns: DataTableProps['dataColumns'] = {
    name: { percentWidth: 20 },
    priority: {},
    severity: {},
    objectAssignee: {
      label: 'Assignees',
      percentWidth: 14,
      isSortable: isRuntimeSort,
    },
    creator: {
      percentWidth: 10,
      isSortable: isRuntimeSort,
    },
    objectLabel: { percentWidth: 10 },
    created: { percentWidth: 10 },
    x_opencti_workflow_id: {},
    objectMarking: {
      isSortable: isRuntimeSort,
    },
  };

  const preloadedPaginationProps = {
    linesQuery: caseIncidentsLinesQuery,
    linesFragment: caseIncidentsLinesFragment,
    queryRef,
    nodePath: ['caseIncidents', 'pageInfo', 'globalCount'],
    setNumberOfElements: storageHelpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<CaseIncidentsLinesCasesPaginationQuery>;

  return (
    <div data-testid="incident-response-page">
      <Breadcrumbs elements={[{ label: t_i18n('Cases') }, { label: t_i18n('Incident responses'), current: true }]} />
      {queryRef && (
        <DataTable
          dataColumns={dataColumns}
          resolvePath={(data: CaseIncidentsLinesCases_data$data) => data.caseIncidents?.edges?.map((n) => n?.node)}
          storageKey={LOCAL_STORAGE_KEY_CASE_INCIDENT}
          initialValues={initialValues}
          toolbarFilters={contextFilters}
          preloadedPaginationProps={preloadedPaginationProps}
          lineFragment={caseIncidentFragment}
          exportContext={{ entity_type: 'Case-Incident' }}
          createButton={(
            <Security needs={[KNOWLEDGE_KNUPDATE]}>
              <div style={{ display: 'flex', marginLeft: 8 }}>
                {hasAvailableForms && (
                  <Tooltip title={t_i18n('Use a form to create an incident response')}>
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
                <CaseIncidentCreation paginationOptions={queryPaginationOptions} />
              </div>
            </Security>
          )}
        />
      )}
      <StixDomainObjectFormSelector
        open={isFormSelectorOpen}
        handleClose={() => setIsFormSelectorOpen(false)}
        entityType="Case-Incident"
      />
    </div>
  );
};

export default CaseIncidents;
