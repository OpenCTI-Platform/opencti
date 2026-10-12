import { useMemo, useState } from 'react';
import { graphql } from 'react-relay';
import { Link } from 'react-router';
import { Stack, Typography } from '@mui/material';
import { OpenInNewOutlined } from '@mui/icons-material';
import { Tabs, TabsList, TabsTrigger } from '@filigran/design-system';
import Button from '@common/button/Button';
import DataTable from '../../../../components/dataGrid/DataTable';
import { DataTableProps } from '../../../../components/dataGrid/dataTableTypes';
import { defaultRender } from '../../../../components/dataGrid/dataTableUtils';
import { useFormatter } from '../../../../components/i18n';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import { UsePreloadedPaginationFragment } from '../../../../utils/hooks/usePreloadedPaginationFragment';
import { emptyFilterGroup, isFilterGroupNotEmpty, useBuildEntityTypeBasedFilterContext } from '../../../../utils/filters/filtersUtils';
import type { FilterGroup } from '../../../../utils/filters/filtersHelpers-types';
import useConnectedDocumentModifier from '../../../../utils/hooks/useConnectedDocumentModifier';
import { PATH_INDICATORS } from '@components/common/routes/paths';
import { buildSavedListFilters, buildSavedListIndicatorsLink, SAVED_LISTS, type SavedListId } from './disseminationAssuranceUtils';
import type { DisseminationAssuranceListsLine_node$data } from './__generated__/DisseminationAssuranceListsLine_node.graphql';
import type { DisseminationAssuranceListsLines_data$data } from './__generated__/DisseminationAssuranceListsLines_data.graphql';
import type {
  DisseminationAssuranceListsLinesPaginationQuery,
  DisseminationAssuranceListsLinesPaginationQuery$variables,
} from './__generated__/DisseminationAssuranceListsLinesPaginationQuery.graphql';

const listsLineFragment = graphql`
  fragment DisseminationAssuranceListsLine_node on Indicator {
    id
    entity_type
    name
    pattern_type
    valid_until
    revoked
    x_opencti_score
    x_opencti_detection
    deployment_platforms_count
    deployment_failed_count
    validated_platforms_count
    hit_platforms_count
    created
    objectMarking {
      id
      definition_type
      definition
      x_opencti_order
      x_opencti_color
    }
  }
`;

const listsLinesQuery = graphql`
  query DisseminationAssuranceListsLinesPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $filters: FilterGroup
    $orderBy: IndicatorsOrdering
    $orderMode: OrderingMode
  ) {
    ...DisseminationAssuranceListsLines_data
    @arguments(
      search: $search
      count: $count
      cursor: $cursor
      filters: $filters
      orderBy: $orderBy
      orderMode: $orderMode
    )
  }
`;

const listsLinesFragment = graphql`
  fragment DisseminationAssuranceListsLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    filters: { type: "FilterGroup" }
    orderBy: { type: "IndicatorsOrdering", defaultValue: created }
    orderMode: { type: "OrderingMode", defaultValue: desc }
  )
  @refetchable(queryName: "DisseminationAssuranceListsLinesRefetchQuery") {
    indicators(
      search: $search
      first: $count
      after: $cursor
      filters: $filters
      orderBy: $orderBy
      orderMode: $orderMode
    ) @connection(key: "Pagination_disseminationAssurance_indicators") {
      edges {
        node {
          id
          ...DisseminationAssuranceListsLine_node
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

const SavedList = ({ listId }: { listId: SavedListId }) => {
  const { t_i18n, n } = useFormatter();
  const LOCAL_STORAGE_KEY = `dissemination-assurance-list-${listId}`;
  const initialValues = {
    searchTerm: '',
    sortBy: 'created',
    orderAsc: false,
    openExports: false,
    filters: emptyFilterGroup,
  };
  const { viewStorage, paginationOptions, helpers: storageHelpers } = usePaginationLocalStorage<DisseminationAssuranceListsLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    initialValues,
    true,
  );
  // The list definition is computed once per mount: "expired" compares valid_until with the opening time.
  const listFilters = useMemo(() => buildSavedListFilters(listId), [listId]);
  const userFilters = useBuildEntityTypeBasedFilterContext('Indicator', viewStorage.filters);
  // The top-level entity type scopes the select-all background tasks of the toolbar to indicators.
  const contextFilters: FilterGroup = {
    mode: 'and',
    filters: [{ key: 'entity_type', values: ['Indicator'], operator: 'eq', mode: 'or' }],
    filterGroups: [listFilters, ...(isFilterGroupNotEmpty(userFilters) ? [userFilters] : [])],
  };
  const queryPaginationOptions = {
    ...paginationOptions,
    filters: contextFilters,
  } as unknown as DisseminationAssuranceListsLinesPaginationQuery$variables;
  const queryRef = useQueryLoading<DisseminationAssuranceListsLinesPaginationQuery>(listsLinesQuery, queryPaginationOptions);
  const preloadedPaginationProps = {
    linesQuery: listsLinesQuery,
    linesFragment: listsLinesFragment,
    queryRef,
    nodePath: ['indicators', 'pageInfo', 'globalCount'],
    setNumberOfElements: storageHelpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<DisseminationAssuranceListsLinesPaginationQuery>;

  const dataColumns: DataTableProps['dataColumns'] = {
    pattern_type: { percentWidth: 9 },
    name: { percentWidth: 17 },
    deployment_platforms_count: {
      id: 'deployment_platforms_count',
      label: t_i18n('Live platforms'),
      percentWidth: 10,
      isSortable: true,
      render: ({ deployment_platforms_count }: DisseminationAssuranceListsLine_node$data) => defaultRender(n(deployment_platforms_count ?? 0)),
    },
    deployment_failed_count: {
      id: 'deployment_failed_count',
      label: t_i18n('Failed deployments'),
      percentWidth: 13,
      isSortable: true,
      render: ({ deployment_failed_count }: DisseminationAssuranceListsLine_node$data) => defaultRender(n(deployment_failed_count ?? 0)),
    },
    validated_platforms_count: {
      id: 'validated_platforms_count',
      label: t_i18n('Validated platforms'),
      percentWidth: 13,
      isSortable: true,
      render: ({ validated_platforms_count }: DisseminationAssuranceListsLine_node$data) => defaultRender(n(validated_platforms_count ?? 0)),
    },
    hit_platforms_count: {
      id: 'hit_platforms_count',
      label: t_i18n('Platforms with hits'),
      percentWidth: 13,
      isSortable: true,
      render: ({ hit_platforms_count }: DisseminationAssuranceListsLine_node$data) => defaultRender(n(hit_platforms_count ?? 0)),
    },
    valid_until: { percentWidth: 15 },
    objectMarking: { percentWidth: 10, isSortable: false },
  };

  return (
    <div data-testid={`dissemination-list-${listId}`}>
      {queryRef && (
        <DataTable
          dataColumns={dataColumns}
          resolvePath={(data: DisseminationAssuranceListsLines_data$data) => data.indicators?.edges?.map((edge) => edge?.node)}
          storageKey={LOCAL_STORAGE_KEY}
          initialValues={initialValues}
          contextFilters={contextFilters}
          lineFragment={listsLineFragment}
          preloadedPaginationProps={preloadedPaginationProps}
          exportContext={{ entity_type: 'Indicator' }}
          entityTypes={['Indicator']}
          emptyStateMessage={t_i18n('No indicator in this list')}
        />
      )}
    </div>
  );
};

const DisseminationAssuranceLists = () => {
  const { t_i18n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Dissemination assurance | Defense'));
  const [listId, setListId] = useState<SavedListId>('disseminated_not_deployed');
  const current = SAVED_LISTS.find((list) => list.id === listId) ?? SAVED_LISTS[0];
  return (
    <div data-testid="dissemination-assurance-lists-page">
      <Tabs value={listId} onValueChange={(value: string) => setListId(value as SavedListId)}>
        <TabsList className="mb-4">
          {SAVED_LISTS.map((list) => (
            <TabsTrigger key={list.id} value={list.id} data-testid={`dissemination-list-tab-${list.id}`}>
              {t_i18n(list.label)}
            </TabsTrigger>
          ))}
        </TabsList>
      </Tabs>
      <Stack direction="row" alignItems="center" justifyContent="space-between" gap={2} sx={{ mb: 2 }}>
        <Typography variant="body2" color="text.secondary">{t_i18n(current.description)}</Typography>
        <Button
          variant="tertiary"
          component={Link}
          to={buildSavedListIndicatorsLink(PATH_INDICATORS, current.id)}
          startIcon={<OpenInNewOutlined fontSize="small" />}
        >
          {t_i18n('Open in indicators')}
        </Button>
      </Stack>
      <SavedList key={current.id} listId={current.id} />
    </div>
  );
};

export default DisseminationAssuranceLists;
