import React, { FunctionComponent } from 'react';
import { AutoFix } from 'mdi-material-ui';
import { useTheme } from '@mui/styles';
import {
  stixCoreRelationshipsFragment,
  stixCoreRelationshipsLinesFragment,
  stixCoreRelationshipsLinesQuery,
} from '@components/common/stix_core_relationships/StixCoreRelationships';
import {
  StixCoreRelationshipsLinesPaginationQuery,
  StixCoreRelationshipsLinesPaginationQuery$variables,
} from '@components/common/stix_core_relationships/__generated__/StixCoreRelationshipsLinesPaginationQuery.graphql';
import { StixCoreRelationshipsLines_data$data } from '@components/common/stix_core_relationships/__generated__/StixCoreRelationshipsLines_data.graphql';
import { getDraftModeColor } from '@components/common/draft/DraftChip';
import DataTable from '../../../../components/dataGrid/DataTable';
import { DataTableProps } from '../../../../components/dataGrid/dataTableTypes';
import ItemIcon from '../../../../components/ItemIcon';
import { itemColor } from '../../../../utils/Colors';
import { UsePreloadedPaginationFragment } from '../../../../utils/hooks/usePreloadedPaginationFragment';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import useAuth from '../../../../utils/hooks/useAuth';
import { emptyFilterGroup, isFilterGroupNotEmpty, useRemoveIdAndIncorrectKeysFromFilterGroupObject } from '../../../../utils/filters/filtersUtils';
import type { FilterGroup } from '../../../../utils/filters/filtersHelpers-types';
import type { Theme } from '../../../../components/Theme';

interface ContainerStixCoreRelationshipsProps {
  containerId: string;
}

/**
 * Builds the filters sent to `stixCoreRelationships`, scoped to relationships
 * that belong to the container.
 */
export const buildContainerRelationshipsContextFilters = (
  containerId: string,
  userFilters: FilterGroup | undefined,
): FilterGroup => ({
  mode: 'and',
  filters: [
    { key: 'objects', values: [containerId], operator: 'eq', mode: 'or' },
    { key: 'entity_type', values: ['stix-core-relationship'], operator: 'eq', mode: 'or' },
  ],
  filterGroups: userFilters && isFilterGroupNotEmpty(userFilters) ? [userFilters] : [],
});

const ContainerStixCoreRelationships: FunctionComponent<ContainerStixCoreRelationshipsProps> = ({ containerId }) => {
  const theme = useTheme<Theme>();
  const {
    platformModuleHelpers: { isRuntimeFieldEnable },
  } = useAuth();
  const isRuntimeSort = isRuntimeFieldEnable() ?? false;
  const LOCAL_STORAGE_KEY = `container-${containerId}-relationships`;

  // Same columns as Data > Relationships.
  const dataColumns: DataTableProps['dataColumns'] = {
    is_inferred: {
      id: 'is_inferred',
      label: ' ',
      isSortable: false,
      percentWidth: 3,
      render: ({ is_inferred, entity_type, draftVersion }) => {
        if (is_inferred) {
          const inferredColor = draftVersion ? getDraftModeColor(theme) : itemColor(entity_type);
          return (<AutoFix style={{ color: inferredColor }} />);
        }
        if (draftVersion) {
          return (<ItemIcon type={entity_type} color={getDraftModeColor(theme)} />);
        }
        return (<ItemIcon type={entity_type} />);
      },
    },
    fromType: {},
    fromName: {},
    relationship_type: {},
    toType: {},
    toName: {},
    createdBy: { percentWidth: 7, isSortable: isRuntimeSort },
    creator: { percentWidth: 7, isSortable: isRuntimeSort },
    created_at: { percentWidth: 12 },
    objectMarking: { isSortable: isRuntimeSort },
  };

  const initialValues = {
    searchTerm: '',
    sortBy: 'created_at',
    orderAsc: false,
    openExports: false,
    filters: emptyFilterGroup,
  };

  const { paginationOptions, viewStorage, helpers: storageHelpers } = usePaginationLocalStorage<StixCoreRelationshipsLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    initialValues,
    true,
  );
  const { filters } = viewStorage;

  // 'objects' (container membership) is mandatory and cannot be widened by user filters.
  const userFilters = useRemoveIdAndIncorrectKeysFromFilterGroupObject(filters, ['stix-core-relationship']);
  const contextFilters = buildContainerRelationshipsContextFilters(containerId, userFilters);

  const queryPaginationOptions = {
    ...paginationOptions,
    filters: contextFilters,
  } as unknown as StixCoreRelationshipsLinesPaginationQuery$variables;

  const queryRef = useQueryLoading<StixCoreRelationshipsLinesPaginationQuery>(
    stixCoreRelationshipsLinesQuery,
    queryPaginationOptions,
  );

  const preloadedPaginationProps = {
    linesQuery: stixCoreRelationshipsLinesQuery,
    linesFragment: stixCoreRelationshipsLinesFragment,
    queryRef,
    nodePath: ['stixCoreRelationships', 'pageInfo', 'globalCount'],
    setNumberOfElements: storageHelpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<StixCoreRelationshipsLinesPaginationQuery>;

  return (
    <div data-testid="container-relationships-page">
      {queryRef && (
        <DataTable
          dataColumns={dataColumns}
          resolvePath={(data: StixCoreRelationshipsLines_data$data) => data.stixCoreRelationships?.edges?.map((n) => n?.node)}
          storageKey={LOCAL_STORAGE_KEY}
          initialValues={initialValues}
          contextFilters={contextFilters}
          lineFragment={stixCoreRelationshipsFragment}
          preloadedPaginationProps={preloadedPaginationProps}
          exportContext={{ entity_id: containerId, entity_type: 'stix-core-relationship' }}
          availableEntityTypes={['stix-core-relationship']}
          // Reaches the toolbar, which needs the type for the relationship-only bulk edits (start and stop times).
          entityTypes={['stix-core-relationship']}
          container={{ id: containerId }}
        />
      )}
    </div>
  );
};

export default ContainerStixCoreRelationships;
