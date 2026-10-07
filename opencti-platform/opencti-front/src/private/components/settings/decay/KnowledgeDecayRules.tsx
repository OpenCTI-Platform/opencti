import React from 'react';
import { graphql } from 'react-relay';
import Alert from '@mui/material/Alert';
import { emptyFilterGroup, useBuildEntityTypeBasedFilterContext } from '../../../../utils/filters/filtersUtils';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { useFormatter } from '../../../../components/i18n';
import ItemBoolean from '../../../../components/ItemBoolean';
import DataTable from '../../../../components/dataGrid/DataTable';
import { DataTableProps } from '../../../../components/dataGrid/dataTableTypes';
import { defaultRender } from '../../../../components/dataGrid/dataTableUtils';
import { UsePreloadedPaginationFragment } from '../../../../utils/hooks/usePreloadedPaginationFragment';
import type { FilterGroup } from '../../../../utils/filters/filtersHelpers-types';
import KnowledgeDecayRuleCreation from './KnowledgeDecayRuleCreation';
import { knowledgeDecayRuleEffect } from './KnowledgeDecayRuleForm';
import { KnowledgeDecayRulesLinesPaginationQuery, KnowledgeDecayRulesLinesPaginationQuery$variables } from './__generated__/KnowledgeDecayRulesLinesPaginationQuery.graphql';
import { KnowledgeDecayRulesLine_node$data } from './__generated__/KnowledgeDecayRulesLine_node.graphql';

const knowledgeDecayRulesQuery = graphql`
  query KnowledgeDecayRulesLinesPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: DecayRuleOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...KnowledgeDecayRulesLines_data
    @arguments(search: $search, count: $count, cursor: $cursor, orderBy: $orderBy, orderMode: $orderMode, filters: $filters)
  }
`;

const knowledgeDecayRulesLinesFragment = graphql`
  fragment KnowledgeDecayRulesLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "DecayRuleOrdering", defaultValue: order }
    orderMode: { type: "OrderingMode", defaultValue: desc }
    filters: { type: "FilterGroup" }
  ) @refetchable(queryName: "KnowledgeDecayRulesLinesRefetchQuery") {
    decayRules(search: $search, first: $count, after: $cursor, orderBy: $orderBy, orderMode: $orderMode, filters: $filters)
    @connection(key: "PaginationKnowledge_decayRules") {
      edges {
        node {
          ...KnowledgeDecayRulesLine_node
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

const knowledgeDecayRulesLineFragment = graphql`
  fragment KnowledgeDecayRulesLine_node on DecayRule {
    id
    name
    entity_type
    created_at
    active
    order
    built_in
    target_scope
    target_types
    freshness_policy
    stale_after_days
    staleElementsCount
  }
`;

// Knowledge decay rules only: indicator decay rules are listed in their own tab
const KNOWLEDGE_SCOPE_FILTERS: FilterGroup = {
  mode: 'and',
  filters: [{ key: 'target_scope', values: ['relationship', 'entity'], operator: 'eq', mode: 'or' }],
  filterGroups: [],
};

const LOCAL_STORAGE_KEY = 'view-knowledge-decay-rules';

const KnowledgeDecayRules = () => {
  const { t_i18n } = useFormatter();
  const initialValues = {
    searchTerm: '',
    sortBy: 'order',
    orderAsc: false,
    openExports: false,
    filters: emptyFilterGroup,
  };
  const { viewStorage, helpers, paginationOptions } = usePaginationLocalStorage<KnowledgeDecayRulesLinesPaginationQuery$variables>(LOCAL_STORAGE_KEY, initialValues);
  const userFilters = useBuildEntityTypeBasedFilterContext('DecayRule', viewStorage.filters);
  const contextFilters: FilterGroup = { mode: 'and', filters: [], filterGroups: [KNOWLEDGE_SCOPE_FILTERS, userFilters as FilterGroup] };
  const queryPaginationOptions = { ...paginationOptions, filters: contextFilters } as unknown as KnowledgeDecayRulesLinesPaginationQuery$variables;
  const queryRef = useQueryLoading<KnowledgeDecayRulesLinesPaginationQuery>(knowledgeDecayRulesQuery, queryPaginationOptions);
  const preloadedPaginationProps = {
    linesQuery: knowledgeDecayRulesQuery,
    linesFragment: knowledgeDecayRulesLinesFragment,
    queryRef,
    nodePath: ['decayRules', 'pageInfo', 'globalCount'],
    setNumberOfElements: helpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<KnowledgeDecayRulesLinesPaginationQuery>;

  const dataColumns: DataTableProps['dataColumns'] = {
    name: { id: 'name', label: t_i18n('Name'), isSortable: false, percentWidth: 21 },
    effect: {
      id: 'effect',
      label: t_i18n('Effect'),
      isSortable: false,
      percentWidth: 51,
      render: (node: KnowledgeDecayRulesLine_node$data) => defaultRender(knowledgeDecayRuleEffect(t_i18n, node)),
    },
    staleElementsCount: {
      id: 'staleElementsCount',
      label: t_i18n('Stale elements'),
      isSortable: false,
      percentWidth: 10,
      render: (node: KnowledgeDecayRulesLine_node$data) => node.staleElementsCount,
    },
    active: {
      id: 'active',
      label: t_i18n('Active'),
      isSortable: false,
      percentWidth: 10,
      render: (node: KnowledgeDecayRulesLine_node$data) => <ItemBoolean label={node.active ? t_i18n('Yes') : t_i18n('No')} status={node.active} />,
    },
    order: { id: 'order', label: t_i18n('Order'), isSortable: false, percentWidth: 8 },
  };

  return (
    <div data-testid="knowledge-decay-rules-page" style={{ margin: 0, padding: '0 200px 0 0' }}>
      <Alert severity="info" variant="outlined" style={{ padding: '0px 10px 0px 10px', marginBottom: 16 }}>
        {t_i18n('Knowledge decay rules age relationships and entities from their last assertion by any source. They never change indicator scores. The highest order applies when several rules match.')}
      </Alert>
      {queryRef && (
        <DataTable
          dataColumns={dataColumns}
          resolvePath={(data) => data.decayRules?.edges?.map(({ node }: { node: KnowledgeDecayRulesLine_node$data }) => node)}
          storageKey={LOCAL_STORAGE_KEY}
          disableLineSelection
          initialValues={initialValues}
          redirectionModeEnabled
          contextFilters={contextFilters}
          lineFragment={knowledgeDecayRulesLineFragment}
          preloadedPaginationProps={preloadedPaginationProps}
          createButton={<KnowledgeDecayRuleCreation paginationOptions={queryPaginationOptions} />}
        />
      )}
    </div>
  );
};

export default KnowledgeDecayRules;
