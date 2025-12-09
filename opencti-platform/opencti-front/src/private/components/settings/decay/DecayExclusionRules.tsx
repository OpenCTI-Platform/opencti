import React from 'react';
import { graphql } from 'react-relay';
import { useFormatter } from 'src/components/i18n';
import { emptyFilterGroup, useBuildEntityTypeBasedFilterContext } from 'src/utils/filters/filtersUtils';
import { usePaginationLocalStorage } from 'src/utils/hooks/useLocalStorage';
import useQueryLoading from 'src/utils/hooks/useQueryLoading';
import { DataTableProps } from 'src/components/dataGrid/dataTableTypes';
import ItemBoolean from 'src/components/ItemBoolean';
import { DecayExclusionRules_node$data } from '@components/settings/decay/__generated__/DecayExclusionRules_node.graphql';
import { UsePreloadedPaginationFragment } from 'src/utils/hooks/usePreloadedPaginationFragment';
import DataTable from 'src/components/dataGrid/DataTable';
import DecayExclusionRuleCreation from '@components/settings/decay/DecayExclusionRuleCreation';
import { DecayExclusionRulesLinesPaginationQuery, DecayExclusionRulesLinesPaginationQuery$variables } from './__generated__/DecayExclusionRulesLinesPaginationQuery.graphql';
import DecayExclusionRulePopover from './DecayExclusionRulePopover';

const decayExclusionRulesQuery = graphql`
  query DecayExclusionRulesLinesPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: DecayExclusionRuleOrdering,
    $orderMode: OrderingMode,
    $filters: FilterGroup,
  ) {
      ...DecayExclusionRulesLines_data
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

const decayExclusionRulesLinesFragment = graphql`
  fragment DecayExclusionRulesLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "DecayExclusionRuleOrdering", defaultValue: name }
    orderMode: { type: "OrderingMode", defaultValue: desc }
    filters: { type: "FilterGroup" }
  ) @refetchable(queryName: "DecayExclusionRuleRefetchQuery") {
    decayExclusionRules(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_decayExclusionRules") {
      edges {
        node {
          ...DecayExclusionRules_node
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

const decayExclusionRulesLineFragment = graphql`
  fragment DecayExclusionRules_node on DecayExclusionRule {
    id
    name
    entity_type
    description
    created_at
    decay_exclusion_filters
    active
  }
`;

const LOCAL_STORAGE_KEY = 'view-decay-exclusion-rules';

const DecayExclusionRules = () => {
  const { t_i18n } = useFormatter();

  const initialValues = {
    searchTerm: '',
    sortBy: 'name',
    orderAsc: true,
    openExports: false,
    filters: emptyFilterGroup,
  };

  const {
    viewStorage,
    paginationOptions,
  } = usePaginationLocalStorage<DecayExclusionRulesLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    initialValues,
  );

  const { filters } = viewStorage;
  const contextFilters = useBuildEntityTypeBasedFilterContext('DecayExclusionRule', filters);

  const queryPaginationOptions = {
    ...paginationOptions,
    filters: contextFilters,
  } as unknown as DecayExclusionRulesLinesPaginationQuery$variables;

  const queryRef = useQueryLoading<DecayExclusionRulesLinesPaginationQuery>(
    decayExclusionRulesQuery,
    queryPaginationOptions,
  );

  const preloadedPaginationProps = {
    linesQuery: decayExclusionRulesQuery,
    linesFragment: decayExclusionRulesLinesFragment,
    queryRef,
    nodePath: ['decayExclusionRules', 'pageInfo', 'globalCount'],
  } as UsePreloadedPaginationFragment<DecayExclusionRulesLinesPaginationQuery>;

  const dataColumns: DataTableProps['dataColumns'] = {
    name: {
      id: 'name',
      label: t_i18n('Name'),
      isSortable: true,
      percentWidth: 50,
    },
    // decay_exclusion_filters: {
    //   id: 'decay_exclusion_observable_types',
    //   label: 'obs',
    //   isSortable: false,
    //   percentWidth: 40,
    //   // render: (node) => (<div>{node.decay_exclusion_filters.join(', ')}</div>),
    // },
    created_at: {
      label: t_i18n('Creation date'),
      percentWidth: 25,
      isSortable: true,
    },
    active: {
      id: 'active ',
      label: t_i18n('Active'),
      percentWidth: 25,
      isSortable: true,
      render: (node: DecayExclusionRules_node$data) => (
        <>
          <ItemBoolean
            variant="inList"
            label={node.active ? t_i18n('Yes') : t_i18n('No')}
            status={node.active}
          />
        </>
      ),
    },
  };

  return (
    <div data-testid='decay-exclusion-rules-page' style={{ margin: 0, padding: '0 200px 0 0' }}>
      {queryRef && (
        <DataTable
          dataColumns={dataColumns}
          resolvePath={(data) => data.decayExclusionRules?.edges?.map(({ node }: { node: DecayExclusionRules_node$data }) => node)}
          storageKey={LOCAL_STORAGE_KEY}
          initialValues={initialValues}
          contextFilters={contextFilters}
          lineFragment={decayExclusionRulesLineFragment}
          disableLineSelection
          disableNavigation
          preloadedPaginationProps={preloadedPaginationProps}
          actions={(row) => <DecayExclusionRulePopover data={row} paginationOptions={queryPaginationOptions} />}
          createButton={<DecayExclusionRuleCreation paginationOptions={queryPaginationOptions} />}
        />
      )}
    </div>
  );
};

export default DecayExclusionRules;
