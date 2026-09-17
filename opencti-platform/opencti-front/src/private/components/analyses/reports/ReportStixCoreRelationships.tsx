import React, { FunctionComponent } from 'react';
import { AutoFix } from 'mdi-material-ui';
import { useTheme } from '@mui/styles';
import { getDraftModeColor } from '@components/common/draft/DraftChip';
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
import DataTable from '../../../../components/dataGrid/DataTable';
import { DataTableProps } from '../../../../components/dataGrid/dataTableTypes';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { UsePreloadedPaginationFragment } from '../../../../utils/hooks/usePreloadedPaginationFragment';
import useAuth from '../../../../utils/hooks/useAuth';
import ItemEntityType from '../../../../components/ItemEntityType';
import ItemIcon from '../../../../components/ItemIcon';
import { itemColor } from '../../../../utils/Colors';
import { emptyFilterGroup, isFilterGroupNotEmpty, useRemoveIdAndIncorrectKeysFromFilterGroupObject } from '../../../../utils/filters/filtersUtils';
import type { Theme } from '../../../../components/Theme';
import type { FilterGroup } from '../../../../utils/filters/filtersHelpers-types';

interface ReportStixCoreRelationshipsProps {
  reportId: string;
}

/**
 * Builds the filters sent to `stixCoreRelationships`, scoped to the relationships referenced
 * by the report (rel_object), never entities-to-entities relationships that merely happen to
 * connect two objects of the report. The 'objects' filter is mandatory and stays outside
 * `userFilters` so it can never be widened or removed by the user.
 */
export const buildReportRelationshipsContextFilters = (
  reportId: string,
  userFilters: FilterGroup | undefined,
): FilterGroup => ({
  mode: 'and',
  filters: [{ key: 'objects', values: [reportId], operator: 'eq', mode: 'or' }],
  filterGroups: userFilters && isFilterGroupNotEmpty(userFilters) ? [userFilters] : [],
});

const ReportStixCoreRelationships: FunctionComponent<ReportStixCoreRelationshipsProps> = ({ reportId }) => {
  const theme = useTheme<Theme>();
  const {
    platformModuleHelpers: { isRuntimeFieldEnable },
  } = useAuth();
  const isRuntimeSort = isRuntimeFieldEnable() ?? false;
  const LOCAL_STORAGE_KEY = `report-${reportId}-relationships`;

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
    fromType: {
      id: 'fromType',
      label: 'From type',
      percentWidth: 9,
      isSortable: false,
      render: (node) => (
        <ItemEntityType showIcon entityType={node.from?.entity_type} isRestricted={!node.from} />
      ),
    },
    fromName: {
      percentWidth: 15,
    },
    relationship_type: {
      percentWidth: 8,
    },
    toType: {
      id: 'toType',
      label: 'To type',
      percentWidth: 9,
      isSortable: false,
      render: (node) => (
        <ItemEntityType showIcon entityType={node.to?.entity_type} isRestricted={!node.to} />
      ),
    },
    toName: {
      percentWidth: 15,
    },
    createdBy: { percentWidth: 8, isSortable: isRuntimeSort },
    creator: { percentWidth: 8, isSortable: isRuntimeSort },
    created_at: { percentWidth: 15 },
    objectMarking: { percentWidth: 10, isSortable: isRuntimeSort },
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

  // 'objects' (report membership) is mandatory and cannot be widened by user filters.
  const userFilters = useRemoveIdAndIncorrectKeysFromFilterGroupObject(filters, ['stix-core-relationship']);
  const contextFilters = buildReportRelationshipsContextFilters(reportId, userFilters);

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
    <div style={{ height: '100%' }}>
      {queryRef && (
        <DataTable
          dataColumns={dataColumns}
          resolvePath={(data: StixCoreRelationshipsLines_data$data) => data.stixCoreRelationships?.edges?.map((n) => n.node)}
          storageKey={LOCAL_STORAGE_KEY}
          initialValues={initialValues}
          contextFilters={contextFilters}
          lineFragment={stixCoreRelationshipsFragment}
          preloadedPaginationProps={preloadedPaginationProps}
          exportContext={{ entity_id: reportId, entity_type: 'stix-core-relationship' }}
          container={{ id: reportId }}
        />
      )}
    </div>
  );
};

export default ReportStixCoreRelationships;
