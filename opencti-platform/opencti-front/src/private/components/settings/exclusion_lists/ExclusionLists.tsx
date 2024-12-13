import CustomizationMenu from '@components/settings/CustomizationMenu';
import React from 'react';
import ExclusionListCreation from '@components/settings/exclusion_lists/ExclusionListCreation';
import { graphql, useQueryLoader } from 'react-relay';
import { UsePreloadedPaginationFragment } from 'src/utils/hooks/usePreloadedPaginationFragment';
import {
  ExclusionListsLinesPaginationQuery,
  ExclusionListsLinesPaginationQuery$variables,
} from '@components/settings/exclusion_lists/__generated__/ExclusionListsLinesPaginationQuery.graphql';
import { ExclusionListsLine_node$data } from '@components/settings/exclusion_lists/__generated__/ExclusionListsLine_node.graphql';
import ExclusionListPopover from '@components/settings/exclusion_lists/ExclusionListPopover';
import Badge from '@mui/material/Badge';
import Grid from '@mui/material/Grid';
import ExclusionListsStatus, { exclusionListsStatusQuery } from '@components/settings/exclusion_lists/ExclusionListsStatus';
import { ExclusionListsStatusQuery } from '@components/settings/exclusion_lists/__generated__/ExclusionListsStatusQuery.graphql';
import { DataTableProps } from '../../../../components/dataGrid/dataTableTypes';
import ItemIcon from '../../../../components/ItemIcon';
import ItemEntityType from '../../../../components/ItemEntityType';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { useFormatter } from '../../../../components/i18n';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import { emptyFilterGroup, useBuildEntityTypeBasedFilterContext } from '../../../../utils/filters/filtersUtils';
import ItemBoolean from '../../../../components/ItemBoolean';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import DataTable from '../../../../components/dataGrid/DataTable';
import EnrichedTooltip from '../../../../components/EnrichedTooltip';

export const exclusionListsQuery = graphql`
  query ExclusionListsLinesPaginationQuery(
    $search: String
    $count: Int!
    $cursor: ID
    $orderBy: ExclusionListOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    ...ExclusionListsLines_data
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

export const exclusionListsFragment = graphql`
  fragment ExclusionListsLines_data on Query
  @argumentDefinitions(
    search: { type: "String" }
    count: { type: "Int", defaultValue: 25 }
    cursor: { type: "ID" }
    orderBy: { type: "ExclusionListOrdering", defaultValue: name }
    orderMode: { type: "OrderingMode", defaultValue: desc }
    filters: { type: "FilterGroup" }
  ) @refetchable(queryName: "ExclusionListsLinesRefetchQuery") {
    exclusionLists(
      search: $search
      first: $count
      after: $cursor
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) @connection(key: "Pagination_exclusionLists") {
      edges {
        node {
          ...ExclusionListsLine_node
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

const exclusionListsLineFragment = graphql`
  fragment ExclusionListsLine_node on ExclusionList {
    id
    name
    description
    enabled
    created_at
    exclusion_list_entity_types
  }
`;

const LOCAL_STORAGE_KEY = 'view-exclusion-lists';

const ExclusionLists = () => {
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
    helpers: storageHelpers,
  } = usePaginationLocalStorage<ExclusionListsLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    initialValues,
  );

  const { filters } = viewStorage;
  const contextFilters = useBuildEntityTypeBasedFilterContext('ExclusionList', filters);

  const queryPaginationOptions = {
    ...paginationOptions,
    filters: contextFilters,
  } as unknown as ExclusionListsLinesPaginationQuery$variables;

  const queryRef = useQueryLoading<ExclusionListsLinesPaginationQuery>(
    exclusionListsQuery,
    queryPaginationOptions,
  );

  const renderEnrichedTooltip = (exclusionListEntityTypes: readonly string[], firstEntityType: string) => (
    <EnrichedTooltip title={
      <Grid container spacing={2} sx={{ marginBottom: '10px' }}>
        {exclusionListEntityTypes.map((type) => (
          <Grid item key={type} xs={6}>
            <ItemEntityType entityType={type} />
          </Grid>
        ))}
      </Grid>
    }
    >
      <div style={{ display: 'flex', margin: '10px 0' }}>
        <Badge variant="dot" color="primary">
          <ItemEntityType entityType={firstEntityType} />
        </Badge>
      </div>
    </EnrichedTooltip>
  );

  const renderExclusionListEntityTypes = (exclusion_list_entity_types: readonly string[]) => {
    const hasMultiple = exclusion_list_entity_types.length > 1;
    const firstEntityType = exclusion_list_entity_types[0];

    return hasMultiple
      ? renderEnrichedTooltip(exclusion_list_entity_types, firstEntityType)
      : <ItemEntityType entityType={firstEntityType} />;
  };

  const dataColumns: DataTableProps['dataColumns'] = {
    icon: {
      id: 'icon',
      label: ' ',
      isSortable: false,
      percentWidth: 3,
      render: () => <ItemIcon type="exclusion-list" />,
    },
    name: {
      id: 'name',
      label: t_i18n('Name'),
      isSortable: true,
      percentWidth: 20,
    },
    description: {
      id: 'description',
      label: t_i18n('Description'),
      percentWidth: 30,
      isSortable: false,
    },
    created_at: {
      label: t_i18n('Creation date'),
      percentWidth: 15,
      isSortable: true,
    },
    enabled: {
      id: 'enabled',
      label: t_i18n('Active'),
      percentWidth: 15,
      isSortable: true,
      render: (node: ExclusionListsLine_node$data) => (
        <ItemBoolean
          variant="inList"
          label={node.enabled ? t_i18n('Yes') : t_i18n('No')}
          status={node.enabled}
        />
      ),
    },
    exclusion_list_entity_types: {
      id: 'exclusion_list_entity_types',
      label: t_i18n('Entity type'),
      percentWidth: 15,
      isSortable: false,
      render: (node: ExclusionListsLine_node$data) => renderExclusionListEntityTypes(node.exclusion_list_entity_types ?? []),
    },
  };

  const preloadedPaginationProps = {
    linesQuery: exclusionListsQuery,
    linesFragment: exclusionListsFragment,
    queryRef,
    nodePath: ['exclusionLists', 'pageInfo', 'globalCount'],
    setNumberOfElements: storageHelpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<ExclusionListsLinesPaginationQuery>;

  const [queryRefStatus, loadQueryStatus] = useQueryLoader<ExclusionListsStatusQuery>(
    exclusionListsStatusQuery,
  );

  const refetchStatus = React.useCallback(() => {
    loadQueryStatus({}, { fetchPolicy: 'store-and-network' });
  }, [queryRefStatus]);

  return (
    <div style={{ margin: 0, padding: '0 200px 0 0' }}>
      <CustomizationMenu />
      <Breadcrumbs elements={[{ label: t_i18n('Settings') }, { label: t_i18n('Customization') }, { label: t_i18n('Exclusion Lists'), current: true }]} />
      <ExclusionListsStatus refetch={refetchStatus} queryRef={queryRefStatus} loadQuery={loadQueryStatus} />
      {queryRef && (
        <DataTable
          dataColumns={dataColumns}
          resolvePath={(data) => data.exclusionLists?.edges?.map(({ node }: { node: ExclusionListsLine_node$data }) => node)}
          storageKey={LOCAL_STORAGE_KEY}
          initialValues={initialValues}
          toolbarFilters={contextFilters}
          lineFragment={exclusionListsLineFragment}
          disableLineSelection
          disableNavigation
          preloadedPaginationProps={preloadedPaginationProps}
          actions={(row) => <ExclusionListPopover data={row} paginationOptions={queryPaginationOptions} refetchStatus={refetchStatus} />}
          message={t_i18n('Exclusion lists can be used to prevent the import of indicators considered benign and legitimate. Exclusion lists only apply to indicators with a STIX pattern.')}
        />
      )}
      <ExclusionListCreation paginationOptions={queryPaginationOptions} refetchStatus={refetchStatus} />
    </div>
  );
};

export default ExclusionLists;
