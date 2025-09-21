import React, { FunctionComponent, useState, useEffect } from 'react';
import { graphql, fetchQuery } from 'react-relay';
import { environment } from '../../../relay/environment';
import IconButton from '@mui/material/IconButton';
import Tooltip from '@mui/material/Tooltip';
import { Assignment } from '@mui/icons-material';
import { CaseRftsLinesCasesPaginationQuery, CaseRftsLinesCasesPaginationQuery$variables } from '@components/cases/__generated__/CaseRftsLinesCasesPaginationQuery.graphql';
import { CaseRftsLinesCases_data$data } from '@components/cases/__generated__/CaseRftsLinesCases_data.graphql';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import useAuth from '../../../utils/hooks/useAuth';
import Security from '../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';
import CaseRftCreation from './case_rfts/CaseRftCreation';
import { emptyFilterGroup, useBuildEntityTypeBasedFilterContext } from '../../../utils/filters/filtersUtils';
import { useFormatter } from '../../../components/i18n';
import Breadcrumbs from '../../../components/Breadcrumbs';
import DataTable from '../../../components/dataGrid/DataTable';
import { UsePreloadedPaginationFragment } from '../../../utils/hooks/usePreloadedPaginationFragment';
import { DataTableProps } from '../../../components/dataGrid/dataTableTypes';
import useConnectedDocumentModifier from '../../../utils/hooks/useConnectedDocumentModifier';
import StixDomainObjectFormSelector from '../common/stix_domain_objects/StixDomainObjectFormSelector';

interface CaseRftsProps {
  inputValue?: string;
}

const caseFragment = graphql`
  fragment CaseRftsLineCases_data on CaseRft {
    id
    name
    description
    entity_type
    created
    takedown_types
    priority
    severity
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

const caseRftsLinesQuery = graphql`
  query CaseRftsLinesCasesPaginationQuery(
    $search: String
    $count: Int
    $cursor: ID
    $orderBy: CaseRftsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...CaseRftsLinesCases_data
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

const caseRftsLinesFragment = graphql`
  fragment CaseRftsLinesCases_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int" }
    cursor: { type: "ID" }
    orderBy: { type: "CaseRftsOrdering" }
    orderMode: { type: "OrderingMode", defaultValue: desc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "CaseRftCasesLinesRefetchQuery") {
    caseRfts(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_case_caseRfts") {
      edges {
        node {
          id
          ...CaseRftsLineCases_data
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

export const LOCAL_STORAGE_KEY = 'caseRfts';

const checkFormsQuery = graphql`
  query CaseRftsCheckFormsQuery {
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

const CaseRfts: FunctionComponent<CaseRftsProps> = () => {
  const { t_i18n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Requests for Takedown | Cases'));
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
              return formEntityType.toLowerCase() === 'case-rft' || formEntityType.toLowerCase() === 'case_rft';
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
  const { viewStorage, helpers: storageHelpers, paginationOptions } = usePaginationLocalStorage<CaseRftsLinesCasesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    initialValues,
  );

  const {
    filters,
  } = viewStorage;

  const contextFilters = useBuildEntityTypeBasedFilterContext('Case-Rft', filters);
  const queryPaginationOptions = {
    ...paginationOptions,
    filters: contextFilters,
  } as unknown as CaseRftsLinesCasesPaginationQuery$variables;
  const queryRef = useQueryLoading<CaseRftsLinesCasesPaginationQuery>(
    caseRftsLinesQuery,
    queryPaginationOptions,
  );

  const isRuntimeSort = isRuntimeFieldEnable() ?? false;
  const dataColumns: DataTableProps['dataColumns'] = {
    name: {
      percentWidth: 21,
    },
    priority: {
      percentWidth: 10,
    },
    severity: {
      percentWidth: 10,
    },
    objectAssignee: {
      percentWidth: 10,
      isSortable: isRuntimeSort,
    },
    creator: {
      percentWidth: 10,
      isSortable: isRuntimeSort,
    },
    objectLabel: {},
    created: {
      percentWidth: 8,
    },
    x_opencti_workflow_id: {},
    objectMarking: {
      isSortable: isRuntimeSort,
    },
  };

  const preloadedPaginationProps = {
    linesQuery: caseRftsLinesQuery,
    linesFragment: caseRftsLinesFragment,
    queryRef,
    nodePath: ['caseRfts', 'pageInfo', 'globalCount'],
    setNumberOfElements: storageHelpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<CaseRftsLinesCasesPaginationQuery>;

  return (
    <div data-testid="rfts-page">
      <Breadcrumbs elements={[{ label: t_i18n('Cases') }, { label: t_i18n('Requests for takedown'), current: true }]} />
      {queryRef && (
        <DataTable
          dataColumns={dataColumns}
          resolvePath={(data: CaseRftsLinesCases_data$data) => data.caseRfts?.edges?.map((n) => n?.node)}
          storageKey={LOCAL_STORAGE_KEY}
          initialValues={initialValues}
          toolbarFilters={contextFilters}
          preloadedPaginationProps={preloadedPaginationProps}
          lineFragment={caseFragment}
          exportContext={{ entity_type: 'Case-Rft' }}
          createButton={(
            <Security needs={[KNOWLEDGE_KNUPDATE]}>
              <div style={{ display: 'flex', marginLeft: 8 }}>
                {hasAvailableForms && (
                  <Tooltip title={t_i18n('Use a form to create a request for takedown')}>
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
                <CaseRftCreation paginationOptions={queryPaginationOptions} />
              </div>
            </Security>
          )}
        />
      )}
      <StixDomainObjectFormSelector
        open={isFormSelectorOpen}
        handleClose={() => setIsFormSelectorOpen(false)}
        entityType="Case-Rft"
      />
    </div>
  );
};

export default CaseRfts;
