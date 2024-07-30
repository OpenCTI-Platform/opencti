import React from 'react';
import { graphql } from 'react-relay';
import { useFormatter } from '../../../components/i18n';
import KillChainPhaseCreation from './kill_chain_phases/KillChainPhaseCreation';
import LabelsVocabulariesMenu from './LabelsVocabulariesMenu';
import Breadcrumbs from '../../../components/Breadcrumbs';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import DataTable from '../../../components/dataGrid/DataTable';
import { useBuildEntityTypeBasedFilterContext } from '../../../utils/filters/filtersUtils';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import KillChainPhasePopover from './kill_chain_phases/KillChainPhasePopover';

const killChainPhasesLinesQuery = graphql`
  query KillChainPhasesLinesPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: KillChainPhasesOrdering
    $orderMode: OrderingMode
  ) {
    ...KillChainPhasesLines_data
    @arguments(
      search: $search
      count: $count
      cursor: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
    )
  }
`;

const linesFragment = graphql`
  fragment KillChainPhasesLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "KillChainPhasesOrdering", defaultValue: phase_name }
    orderMode: { type: "OrderingMode", defaultValue: asc }
  )
  @refetchable(queryName: "KillChainPhasesRefetchPaginationQuery"){
    killChainPhases(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
    ) @connection(key: "Pagination_killChainPhases") {
      edges {
        node {
          ...KillChainPhasesLine_node
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

const lineFragment = graphql`
  fragment KillChainPhasesLine_node on KillChainPhase {
    id
    kill_chain_name
    phase_name
    x_opencti_order
    created
    modified
    editContext {
      focusOn
      name
    }
  }
`;

export const killChainPhasesSearchQuery = graphql`
  query KillChainPhasesSearchQuery($search: String) {
    killChainPhases(search: $search) {
      edges {
        node {
          id
          kill_chain_name
          phase_name
          x_opencti_order
        }
      }
    }
  }
`;

const LOCAL_STORAGE_KEY = 'killChainPhases';

const KillChainPhases = () => {
  const { t_i18n } = useFormatter();

  const initialValues = {
    sortBy: 'x_opencti_order',
    orderAsc: true,
    searchTerm: '',
  };
  const { viewStorage: { filters }, paginationOptions, helpers } = usePaginationLocalStorage(LOCAL_STORAGE_KEY, initialValues);

  const contextFilters = useBuildEntityTypeBasedFilterContext('Kill-Chain-Phase', filters);
  const queryPaginationOptions = {
    ...paginationOptions,
    filters: contextFilters,
  };

  const queryRef = useQueryLoading(
    killChainPhasesLinesQuery,
    queryPaginationOptions,
  );

  const dataColumns = {
    kill_chain_name: {},
    phase_name: {},
    x_opencti_order: {},
    created: { percentWidth: 15 },
  };

  const preloadedPaginationProps = {
    linesQuery: killChainPhasesLinesQuery,
    linesFragment,
    queryRef,
    nodePath: ['killChainPhases', 'pageInfo', 'globalCount'],
    setNumberOfElements: helpers.handleSetNumberOfElements,
  };

  return (
    <div style={{ marginRight: 200 }}>
      <LabelsVocabulariesMenu />
      <Breadcrumbs variant="list" elements={[{ label: t_i18n('Settings') }, { label: t_i18n('Taxonomies') }, { label: t_i18n('Kill chain phases'), current: true }]} />
      {queryRef && (
        <DataTable
          dataColumns={dataColumns}
          resolvePath={(data) => data.killChainPhases.edges.map(({ node }) => node)}
          storageKey={LOCAL_STORAGE_KEY}
          initialValues={initialValues}
          toolbarFilters={contextFilters}
          lineFragment={lineFragment}
          preloadedPaginationProps={preloadedPaginationProps}
          actions={(killChainPhase) => <KillChainPhasePopover killChainPhase={killChainPhase} paginationOptions={queryPaginationOptions} />}
          searchContextFinal={{ entityTypes: ['Kill-Chain-Phases'] }}
          disableNavigation
        />
      )}
      <KillChainPhaseCreation paginationOptions={queryPaginationOptions} />
    </div>
  );
};

export default KillChainPhases;
