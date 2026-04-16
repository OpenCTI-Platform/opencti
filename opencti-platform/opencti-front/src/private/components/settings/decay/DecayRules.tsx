import React from 'react';
import Alert from '@mui/material/Alert';
import { emptyFilterGroup, useBuildEntityTypeBasedFilterContext } from '../../../../utils/filters/filtersUtils';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import DecayRuleCreation from './DecayRuleCreation';
import { useFormatter } from '../../../../components/i18n';
import ItemBoolean from '../../../../components/ItemBoolean';
import { DecayRulesLinesPaginationQuery, DecayRulesLinesPaginationQuery$variables } from './__generated__/DecayRulesLinesPaginationQuery.graphql';
import { DecayRulesLine_node$data } from './__generated__/DecayRulesLine_node.graphql';
import useAuth from '../../../../utils/hooks/useAuth';
import { INDICATOR_DECAY_MANAGER } from '../../../../utils/platformModulesHelper';
import useConnectedDocumentModifier from '../../../../utils/hooks/useConnectedDocumentModifier';
import { DataTableProps } from 'src/components/dataGrid/dataTableTypes';
import DataTable from 'src/components/dataGrid/DataTable';
import { UsePreloadedPaginationFragment } from 'src/utils/hooks/usePreloadedPaginationFragment';
import { graphql } from 'react-relay';

export const decayRulesQuery = graphql`
  query DecayRulesLinesPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: DecayRuleOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...DecayRulesLines_data
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
export const decayRulesLinesFragment = graphql`
  fragment DecayRulesLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "DecayRuleOrdering", defaultValue: order }
    orderMode: { type: "OrderingMode", defaultValue: desc }
    filters: { type: "FilterGroup" }
  ) @refetchable(queryName: "DecayRulesLinesRefetchQuery") {
    decayRules(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_decayRules") {
      edges {
        node {
          ...DecayRulesLine_node
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

const decayRulesLineFragment = graphql`
  fragment DecayRulesLine_node on DecayRule {
    id
    name
    description
    entity_type
    created_at
    updated_at
    active
    order
    built_in
    appliedIndicatorsCount
  }
`;

const LOCAL_STORAGE_KEY = 'view-decay-rules';

const DecayRules = () => {
  const { t_i18n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();
  const { platformModuleHelpers } = useAuth();

  setTitle(t_i18n('Decay Rules | Customization | Settings'));

  const initialValues = {
    searchTerm: '',
    sortBy: 'order',
    orderAsc: false,
    openExports: false,
    filters: emptyFilterGroup,
  };

  const { viewStorage, paginationOptions } = usePaginationLocalStorage<DecayRulesLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    initialValues,
  );

  const { filters } = viewStorage;
  const contextFilters = useBuildEntityTypeBasedFilterContext('DecayRule', filters);

  const queryPaginationOptions = {
    ...paginationOptions,
    filters: contextFilters,
  } as unknown as DecayRulesLinesPaginationQuery$variables;

  const queryRef = useQueryLoading<DecayRulesLinesPaginationQuery>(
    decayRulesQuery,
    queryPaginationOptions,
  );

  const preloadedPaginationProps = {
    linesQuery: decayRulesQuery,
    linesFragment: decayRulesLinesFragment,
    queryRef,
    nodePath: ['decayRules', 'pageInfo', 'globalCount'],
  } as UsePreloadedPaginationFragment<DecayRulesLinesPaginationQuery>;

  const dataColumns: DataTableProps['dataColumns'] = {
    name: {
      id: 'name',
      label: t_i18n('Name'),
      isSortable: false,
      percentWidth: 30,
    },
    created_at: {
      id: 'created_at',
      label: t_i18n('Creation date'),
      isSortable: false,
      percentWidth: 20,
    },
    appliedIndicatorsCount: {
      id: 'appliedIndicatorsCount',
      label: t_i18n('Impacted indicators'),
      isSortable: false,
      percentWidth: 20,
      render: (node: DecayRulesLine_node$data) => node.appliedIndicatorsCount,
    },
    active: {
      id: 'active',
      label: t_i18n('Active'),
      isSortable: false,
      percentWidth: 15,
      render: (node: DecayRulesLine_node$data) => (
        <ItemBoolean
          label={node.active ? t_i18n('Yes') : t_i18n('No')}
          status={node.active}
        />
      ),
    },
    order: {
      id: 'order',
      label: t_i18n('Order'),
      isSortable: false,
      percentWidth: 15,
    },
  };

  const alertContent = platformModuleHelpers.generateDisableMessage(INDICATOR_DECAY_MANAGER);

  return (
    <div data-testid="decay-rules-page" style={{ margin: 0, padding: '0 200px 0 0' }}>
      {!platformModuleHelpers.isIndicatorDecayManagerEnable() && alertContent && (
        <Alert
          severity="info"
          variant="outlined"
          style={{ padding: '0px 10px 0px 10px' }}
        >
          {t_i18n(alertContent)}
        </Alert>
      )}
      {queryRef && (
        <DataTable
          dataColumns={dataColumns}
          resolvePath={(data) => data.decayRules?.edges?.map(({ node }: { node: DecayRulesLine_node$data }) => node)}
          storageKey={LOCAL_STORAGE_KEY}
          disableLineSelection
          initialValues={initialValues}

          redirectionModeEnabled
          contextFilters={contextFilters}
          lineFragment={decayRulesLineFragment}
          preloadedPaginationProps={preloadedPaginationProps}
          createButton={<DecayRuleCreation paginationOptions={queryPaginationOptions} />}
        />
      )}
    </div>
  );
};

export default DecayRules;
