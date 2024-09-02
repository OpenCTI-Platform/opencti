import React from 'react';
import { graphql } from 'react-relay';
import { AttackPatternsLinesPaginationQuery, AttackPatternsLinesPaginationQuery$variables } from '@components/techniques/__generated__/AttackPatternsLinesPaginationQuery.graphql';
import Tooltip from '@mui/material/Tooltip';
import { AttackPatternsLines_data$data } from '@components/techniques/__generated__/AttackPatternsLines_data.graphql';
import AttackPatternCreation from './attack_patterns/AttackPatternCreation';
import Security from '../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';
import { usePaginationLocalStorage } from '../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import { useBuildEntityTypeBasedFilterContext, emptyFilterGroup } from '../../../utils/filters/filtersUtils';
import { useFormatter } from '../../../components/i18n';
import Breadcrumbs from '../../../components/Breadcrumbs';
import DataTable from '../../../components/dataGrid/DataTable';
import { UsePreloadedPaginationFragment } from '../../../utils/hooks/usePreloadedPaginationFragment';
import { truncate } from '../../../utils/String';
import { DataTableProps } from '../../../components/dataGrid/dataTableTypes';
import useHelper from '../../../utils/hooks/useHelper';

const LOCAL_STORAGE_KEY = 'attackPattern';

const attackPatternLineFragment = graphql`
  fragment AttackPatternsLine_node on AttackPattern {
    id
    entity_type
    name
    x_mitre_id
    created
    modified
    objectLabel {
      id
      value
      color
    }
    killChainPhases {
      kill_chain_name
      phase_name
    }
  }
`;

export const attackPatternsLinesQuery = graphql`
  query AttackPatternsLinesPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: AttackPatternsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...AttackPatternsLines_data
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

const attackPatternsLinesFragment = graphql`
  fragment AttackPatternsLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "AttackPatternsOrdering", defaultValue: name }
    orderMode: { type: "OrderingMode", defaultValue: asc }
    filters: { type: "FilterGroup" }
  )
  @refetchable(queryName: "AttackPatternsLinesRefetchQuery") {
    attackPatterns(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_attackPatterns") {
      edges {
        node {
          name
          ...AttackPatternsLine_node
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

const AttackPatterns = () => {
  const { t_i18n } = useFormatter();
  const { isFeatureEnable } = useHelper();
  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');
  const initialValues = {
    searchTerm: '',
    sortBy: 'name',
    orderAsc: true,
    openExports: false,
    filters: emptyFilterGroup,
  };
  const { viewStorage, helpers: storageHelpers, paginationOptions } = usePaginationLocalStorage<AttackPatternsLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    initialValues,
  );

  const {
    filters,
  } = viewStorage;
  const contextFilters = useBuildEntityTypeBasedFilterContext('Attack-Pattern', filters);
  const queryPaginationOptions = {
    ...paginationOptions,
    filters: contextFilters,
  } as unknown as AttackPatternsLinesPaginationQuery$variables;

  const dataColumns: DataTableProps['dataColumns'] = {
    killChainPhase: {},
    x_mitre_id: {},
    name: {
      percentWidth: 30,
      render: ({ name }, { column: { size } }) => (<Tooltip title={name}>{truncate(name, size * 0.113)}</Tooltip>),
    },
    objectLabel: {},
    created: {},
    modified: {},
  };
  const queryRef = useQueryLoading<AttackPatternsLinesPaginationQuery>(
    attackPatternsLinesQuery,
    queryPaginationOptions,
  );

  const preloadedPaginationOptions = {
    linesQuery: attackPatternsLinesQuery,
    linesFragment: attackPatternsLinesFragment,
    queryRef,
    nodePath: ['attackPatterns', 'pageInfo', 'globalCount'],
    setNumberOfElements: storageHelpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<AttackPatternsLinesPaginationQuery>;

  return (
    <>
      <Breadcrumbs variant="list" elements={[{ label: t_i18n('Techniques') }, { label: t_i18n('Attack patterns'), current: true }]} />
      {queryRef && (
        <DataTable
          dataColumns={dataColumns}
          resolvePath={(data: AttackPatternsLines_data$data) => data.attackPatterns?.edges?.map((n) => n?.node)}
          storageKey={LOCAL_STORAGE_KEY}
          initialValues={initialValues}
          toolbarFilters={contextFilters}
          preloadedPaginationProps={preloadedPaginationOptions}
          lineFragment={attackPatternLineFragment}
          exportContext={{ entity_type: 'Attack-Pattern' }}
          createButton={isFABReplaced && (
            <Security needs={[KNOWLEDGE_KNUPDATE]}>
              <AttackPatternCreation paginationOptions={paginationOptions} />
            </Security>
          )}
        />
      )}
      {!isFABReplaced && (
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <AttackPatternCreation paginationOptions={paginationOptions} />
        </Security>
      )}
    </>
  );
};

export default AttackPatterns;
