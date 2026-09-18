import React, { FunctionComponent } from 'react';
import {
  stixCoreRelationshipsLinesFragment,
  stixCoreRelationshipsLinesQuery,
} from '@components/common/stix_core_relationships/StixCoreRelationships';
import {
  StixCoreRelationshipsLinesPaginationQuery,
  StixCoreRelationshipsLinesPaginationQuery$variables,
} from '@components/common/stix_core_relationships/__generated__/StixCoreRelationshipsLinesPaginationQuery.graphql';
import ListLines from '../../../../components/list_lines/ListLines';
import { DataColumns } from '../../../../components/list_lines';
import ToolBar from '../../data/ToolBar';
import useEntityToggle from '../../../../utils/hooks/useEntityToggle';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import useAuth from '../../../../utils/hooks/useAuth';
import { useFormatter } from '../../../../components/i18n';
import { emptyFilterGroup, isFilterGroupNotEmpty, useRemoveIdAndIncorrectKeysFromFilterGroupObject } from '../../../../utils/filters/filtersUtils';
import type { Theme } from '../../../../components/Theme';
import type { FilterGroup } from '../../../../utils/filters/filtersHelpers-types';
import ReportStixCoreRelationshipsLines from './ReportStixCoreRelationshipsLines';
import type { ReportRelationshipNode } from './ReportStixCoreRelationshipsLine';

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
  const { t_i18n } = useFormatter();
  const {
    platformModuleHelpers: { isRuntimeFieldEnable },
  } = useAuth();
  const isRuntimeSort = isRuntimeFieldEnable() ?? false;
  const LOCAL_STORAGE_KEY = `report-${reportId}-relationships`;

  const dataColumns: DataColumns = {
    fromType: {
      label: 'From type',
      width: '11%',
      isSortable: false,
    },
    fromName: {
      label: 'From name',
      width: '16%',
      isSortable: false,
    },
    relationship_type: {
      label: 'Relationship type',
      width: '12%',
      isSortable: true,
    },
    toType: {
      label: 'To type',
      width: '11%',
      isSortable: false,
    },
    toName: {
      label: 'To name',
      width: '16%',
      isSortable: false,
    },
    createdBy: { label: 'Author', width: '9%', isSortable: isRuntimeSort },
    created_at: { label: 'Created', width: '9%', isSortable: true },
    objectMarking: { label: 'Marking', width: '8%', isSortable: isRuntimeSort },
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
  const {
    selectedElements,
    deSelectedElements,
    selectAll,
    numberOfSelectedElements,
    handleClearSelectedElements,
    handleToggleSelectAll,
    onToggleEntity,
  } = useEntityToggle<ReportRelationshipNode>(LOCAL_STORAGE_KEY);

  return queryRef ? (
    <>
      <ListLines
        helpers={storageHelpers}
        sortBy={viewStorage.sortBy}
        orderAsc={viewStorage.orderAsc}
        dataColumns={dataColumns}
        handleSort={storageHelpers.handleSort}
        handleSearch={storageHelpers.handleSearch}
        handleAddFilter={storageHelpers.handleAddFilter}
        handleRemoveFilter={storageHelpers.handleRemoveFilter}
        handleSwitchGlobalMode={storageHelpers.handleSwitchGlobalMode}
        handleSwitchLocalMode={storageHelpers.handleSwitchLocalMode}
        handleToggleSelectAll={handleToggleSelectAll}
        selectAll={selectAll}
        keyword={viewStorage.searchTerm}
        filters={filters}
        handleToggleExports={storageHelpers.handleToggleExports}
        openExports={viewStorage.openExports}
        iconExtension={true}
        numberOfElements={viewStorage.numberOfElements}
        paginationOptions={queryPaginationOptions}
        availableEntityTypes={['stix-core-relationship']}
        availableRelationshipTypes={[]}
        exportContext={{ entity_id: reportId, entity_type: 'stix-core-relationship' }}
        noPadding={true}
        disableCards={true}
        entityTypes={['stix-core-relationship']}
      >
        <ReportStixCoreRelationshipsLines
          dataColumns={dataColumns}
          paginationOptions={queryPaginationOptions}
          queryRef={queryRef}
          setNumberOfElements={storageHelpers.handleSetNumberOfElements}
          selectedElements={selectedElements}
          deSelectedElements={deSelectedElements}
          selectAll={selectAll}
          onToggleEntity={onToggleEntity}
        />
        <ToolBar
          selectedElements={selectedElements}
          deSelectedElements={deSelectedElements}
          numberOfSelectedElements={numberOfSelectedElements}
          selectAll={selectAll}
          filters={contextFilters}
          search={viewStorage.searchTerm}
          handleClearSelectedElements={handleClearSelectedElements}
          container={{ id: reportId }}
          warning={true}
          warningMessage={t_i18n('Be careful, you are about to delete the selected relationships')}
          type="stix-core-relationship"
        />
      </ListLines>
    </>
  ) : null;
};

export default ReportStixCoreRelationships;
