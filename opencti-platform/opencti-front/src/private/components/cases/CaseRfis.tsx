import React, { FunctionComponent, useState, useEffect } from 'react';
import { graphql, fetchQuery } from 'react-relay';
import { environment } from '../../../relay/environment';
import IconButton from '@mui/material/IconButton';
import Tooltip from '@mui/material/Tooltip';
import { Assignment } from '@mui/icons-material';
import { CaseRfisLinesCasesPaginationQuery, CaseRfisLinesCasesPaginationQuery$variables } from '@components/cases/__generated__/CaseRfisLinesCasesPaginationQuery.graphql';
import { CaseRfisLinesCases_data$data } from '@components/cases/__generated__/CaseRfisLinesCases_data.graphql';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import useAuth from '../../../utils/hooks/useAuth';
import Security from '../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';
import CaseRfiCreation from './case_rfis/CaseRfiCreation';
import { emptyFilterGroup, useBuildEntityTypeBasedFilterContext } from '../../../utils/filters/filtersUtils';
import { useFormatter } from '../../../components/i18n';
import Breadcrumbs from '../../../components/Breadcrumbs';
import DataTable from '../../../components/dataGrid/DataTable';
import { UsePreloadedPaginationFragment } from '../../../utils/hooks/usePreloadedPaginationFragment';
import useConnectedDocumentModifier from '../../../utils/hooks/useConnectedDocumentModifier';
import StixDomainObjectFormSelector from '../common/stix_domain_objects/StixDomainObjectFormSelector';

interface CaseRfisProps {
  inputValue?: string;
}

const caseFragment = graphql`
  fragment CaseRfisLineCase_node on CaseRfi {
    id
    name
    description
    created
    information_types
    priority
    severity
    entity_type
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

const caseRfisLinesQuery = graphql`
  query CaseRfisLinesCasesPaginationQuery(
    $search: String
    $count: Int
    $cursor: ID
    $orderBy: CaseRfisOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...CaseRfisLinesCases_data
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

const caseRfisLinesFragment = graphql`
  fragment CaseRfisLinesCases_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int" }
    cursor: { type: "ID" }
    orderBy: { type: "CaseRfisOrdering" }
    orderMode: { type: "OrderingMode", defaultValue: desc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "CaseRfiCasesLinesRefetchQuery") {
    caseRfis(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_case_caseRfis") {
      edges {
        node {
          id
          ...CaseRfisLineCase_node
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

export const LOCAL_STORAGE_KEY = 'caseRfis';

const checkFormsQuery = graphql`
  query CaseRfisCheckFormsQuery {
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

const CaseRfis: FunctionComponent<CaseRfisProps> = () => {
  const { t_i18n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Requests for Information | Cases'));
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
              return formEntityType.toLowerCase() === 'case-rfi' || formEntityType.toLowerCase() === 'case_rfi';
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
  const { viewStorage, helpers: storageHelpers, paginationOptions } = usePaginationLocalStorage<CaseRfisLinesCasesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    initialValues,
  );

  const {
    filters,
  } = viewStorage;
  const contextFilters = useBuildEntityTypeBasedFilterContext('Case-Rfi', filters);
  const queryPaginationOptions = {
    ...paginationOptions,
    filters: contextFilters,
  } as unknown as CaseRfisLinesCasesPaginationQuery$variables;
  const queryRef = useQueryLoading<CaseRfisLinesCasesPaginationQuery>(
    caseRfisLinesQuery,
    queryPaginationOptions,
  );

  const isRuntimeSort = isRuntimeFieldEnable() ?? false;
  const dataColumns = {
    name: {
      label: 'Name',
      percentWidth: 20,
      isSortable: true,
    },
    priority: {},
    severity: {},
    objectAssignee: {},
    creator: {
      percentWidth: 10,
      isSortable: isRuntimeSort,
    },
    objectLabel: {},
    created: {
      percentWidth: 9,
    },
    x_opencti_workflow_id: {},
    objectMarking: {
      isSortable: isRuntimeSort,
    },
  };

  const preloadedPaginationProps = {
    linesQuery: caseRfisLinesQuery,
    linesFragment: caseRfisLinesFragment,
    queryRef,
    nodePath: ['caseRfis', 'pageInfo', 'globalCount'],
    setNumberOfElements: storageHelpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<CaseRfisLinesCasesPaginationQuery>;

  return (
    <div data-testid="rfis-page">
      <Breadcrumbs elements={[{ label: t_i18n('Cases') }, { label: t_i18n('Requests for information'), current: true }]} />
      {queryRef && (
        <DataTable
          dataColumns={dataColumns}
          resolvePath={(data: CaseRfisLinesCases_data$data) => data.caseRfis?.edges?.map((n) => n?.node)}
          storageKey={LOCAL_STORAGE_KEY}
          initialValues={initialValues}
          toolbarFilters={contextFilters}
          preloadedPaginationProps={preloadedPaginationProps}
          lineFragment={caseFragment}
          exportContext={{ entity_type: 'Case-Rfi' }}
          createButton={(
            <Security needs={[KNOWLEDGE_KNUPDATE]}>
              <div style={{ display: 'flex', marginLeft: 8 }}>
                {hasAvailableForms && (
                  <Tooltip title={t_i18n('Use a form to create a request for information')}>
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
                <CaseRfiCreation paginationOptions={queryPaginationOptions} />
              </div>
            </Security>
          )}
        />
      )}
      <StixDomainObjectFormSelector
        open={isFormSelectorOpen}
        handleClose={() => setIsFormSelectorOpen(false)}
        entityType="Case-Rfi"
      />
    </div>
  );
};

export default CaseRfis;
