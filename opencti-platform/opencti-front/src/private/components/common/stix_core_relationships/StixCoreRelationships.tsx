import React, { FunctionComponent } from 'react';
import {
  RelationshipsStixCoreRelationshipsLinesPaginationQuery,
  RelationshipsStixCoreRelationshipsLinesPaginationQuery$variables,
} from '@components/data/__generated__/RelationshipsStixCoreRelationshipsLinesPaginationQuery.graphql';
import {
  relationshipsStixCoreRelationshipsLineFragment,
  relationshipsStixCoreRelationshipsLinesFragment,
  relationshipsStixCoreRelationshipsLinesQuery,
} from '@components/data/Relationships';
import { RelationshipsStixCoreRelationshipsLines_data$data } from '@components/data/__generated__/RelationshipsStixCoreRelationshipsLines_data.graphql';
import { AutoFix, ProgressWrench, RelationManyToMany } from 'mdi-material-ui';
import ToggleButton from '@mui/material/ToggleButton';
import Tooltip from '@mui/material/Tooltip';
import { ViewColumnOutlined } from '@mui/icons-material';
import FiligranIcon from '@components/common/FiligranIcon';
import { ListViewIcon, SublistViewIcon } from 'filigran-icon';
import useAuth from '../../../../utils/hooks/useAuth';
import { emptyFilterGroup, isFilterGroupNotEmpty, useRemoveIdAndIncorrectKeysFromFilterGroupObject } from '../../../../utils/filters/filtersUtils';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import DataTable from '../../../../components/dataGrid/DataTable';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { UsePreloadedPaginationFragment } from '../../../../utils/hooks/usePreloadedPaginationFragment';
import ItemEntityType from '../../../../components/ItemEntityType';
import ItemIcon from '../../../../components/ItemIcon';
import { itemColor } from '../../../../utils/Colors';
import { FilterGroup } from '../../../../utils/filters/filtersHelpers-types';
import { PaginationOptions } from '../../../../components/list_lines';
import { DataTableProps } from '../../../../components/dataGrid/dataTableTypes';
import { useFormatter } from '../../../../components/i18n';

interface StixCoreRelationshipsProps {
  storageKey: string;
  entityId: string;
  currentView?: string;
  paginationOptions: PaginationOptions;
  targetTypes: string[]
  direction: 'fromEntity' | 'toEntity' | 'all'
  relationshipTypes: string[]
}

const StixCoreRelationships: FunctionComponent<StixCoreRelationshipsProps> = (
  {
    storageKey,
    entityId,
    currentView,
    paginationOptions,
    targetTypes,
    direction,
    relationshipTypes,
  },
) => {
  const {
    platformModuleHelpers: { isRuntimeFieldEnable },
  } = useAuth();
  const { t_i18n } = useFormatter();
  const isRuntimeSort = isRuntimeFieldEnable() ?? false;
  const dataColumns: DataTableProps['dataColumns'] = {
    is_inferred: {
      id: 'is_inferred',
      label: ' ',
      isSortable: false,
      percentWidth: 3,
      render: ({ is_inferred, entity_type }) => (is_inferred ? <AutoFix style={{ color: itemColor(entity_type) }} /> : <ItemIcon type={entity_type} />),
    },
    fromType: {
      id: 'fromType',
      label: 'From type',
      percentWidth: 10,
      isSortable: false,
      render: (node) => (
        <ItemEntityType inList showIcon entityType={node.from?.entity_type} isRestricted={!node.from} />
      ),
    },
    relationship_type: {
      percentWidth: 10,
    },
    toType: {
      id: 'toType',
      label: 'To type',
      percentWidth: 10,
      isSortable: false,
      render: (node) => (
        <ItemEntityType inList showIcon entityType={node.to?.entity_type} isRestricted={!node.to} />
      ),
    },
    toName: {
      percentWidth: 25,
    },
    createdBy: { percentWidth: 10, isSortable: isRuntimeSort },
    creator: { percentWidth: 10, isSortable: isRuntimeSort },
    created_at: { percentWidth: 15 },
    objectMarking: { isSortable: isRuntimeSort },
  };

  const initialValues = {
    searchTerm: '',
    sortBy: 'name',
    orderAsc: true,
    openExports: false,
    filters: emptyFilterGroup,
    view: currentView,
  };

  const { viewStorage, helpers: storageHelpers } = usePaginationLocalStorage<RelationshipsStixCoreRelationshipsLinesPaginationQuery$variables>(
    storageKey,
    initialValues,
  );
  const {
    filters,
  } = viewStorage;

  // Filters due to screen context
  const userFilters = useRemoveIdAndIncorrectKeysFromFilterGroupObject(filters, ['stix-core-relationship']);
  const predefinedFilters = [{ key: 'relationship_type', values: relationshipTypes }];
  if (direction === 'all') {
    predefinedFilters.push({ key: 'fromOrToId', values: [entityId] });
    predefinedFilters.push({ key: 'elementWithTargetTypes', values: targetTypes });
  } else if (direction === 'toEntity') {
    predefinedFilters.push({ key: 'toId', values: [entityId] });
    // if (role) predefinedFilters.push({ key: 'toRole', values: [role] });
    predefinedFilters.push({ key: 'fromTypes', values: targetTypes });
  } else {
    predefinedFilters.push({ key: 'fromId', values: [entityId] });
    // if (role) predefinedFilters.push({ key: 'fromRole', values: [role] });
    predefinedFilters.push({ key: 'toTypes', values: targetTypes });
  }
  const contextFilters: FilterGroup = {
    mode: 'and',
    filters: predefinedFilters,
    filterGroups: userFilters && isFilterGroupNotEmpty(userFilters) ? [userFilters] : [],
  };

  const queryPaginationOptions = {
    ...paginationOptions,
    filters: contextFilters,
  } as unknown as RelationshipsStixCoreRelationshipsLinesPaginationQuery$variables;

  const queryRef = useQueryLoading<RelationshipsStixCoreRelationshipsLinesPaginationQuery>(
    relationshipsStixCoreRelationshipsLinesQuery,
    queryPaginationOptions,
  );
  const preloadedPaginationProps = {
    linesQuery: relationshipsStixCoreRelationshipsLinesQuery,
    linesFragment: relationshipsStixCoreRelationshipsLinesFragment,
    queryRef,
    nodePath: ['stixCoreRelationships', 'pageInfo', 'globalCount'],
    setNumberOfElements: storageHelpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<RelationshipsStixCoreRelationshipsLinesPaginationQuery>;

  return (
    <div
      style={{
        transform: 'translateY(-12px)',
      }}
    >      {queryRef && (
      <DataTable
        dataColumns={dataColumns}
        resolvePath={(data: RelationshipsStixCoreRelationshipsLines_data$data) => data.stixCoreRelationships?.edges?.map((n) => n.node)}
        storageKey={storageKey}
        initialValues={initialValues}
        toolbarFilters={contextFilters}
        lineFragment={relationshipsStixCoreRelationshipsLineFragment}
        preloadedPaginationProps={preloadedPaginationProps}
        exportContext={{ entity_type: 'Attack-Pattern' }}
        additionalHeaderButtons={[
          (<ToggleButton key="matrix" value="matrix" aria-label="matrix">
            <Tooltip title={t_i18n('Matrix view')}>
              <ViewColumnOutlined fontSize="small" color="primary" />
            </Tooltip>
          </ToggleButton>),
          (<Tooltip key="matrix-in-line" title={t_i18n('Matrix in line view')}>
            <ToggleButton key="matrix-in-line" value="matrix-in-line" aria-label="matrix-in-line">
              <FiligranIcon icon={ListViewIcon} size="small" color={currentView === 'matrix-in-line' ? 'secondary' : 'primary'} />
            </ToggleButton>
          </Tooltip>
          ),
          (<Tooltip key="list" title={t_i18n('Kill chain view')}>
            <ToggleButton key="list" value="list" aria-label="list">
              <FiligranIcon icon={SublistViewIcon} size="small" color={currentView === 'list' ? 'secondary' : 'primary'} />
            </ToggleButton>
          </Tooltip>
          ),
          (<ToggleButton key="courses-of-action" value="courses-of-action" aria-label="courses-of-action">
            <Tooltip title={t_i18n('Courses of action view')}>
              <ProgressWrench color={currentView === 'courses-of-action' ? 'secondary' : 'primary'} fontSize="small" />
            </Tooltip>
          </ToggleButton>),
          (<ToggleButton key="relationships" value="relationships" aria-label="relationships">
            <Tooltip title={t_i18n('Relationships view')}>
              <RelationManyToMany fontSize="small" color={currentView === 'relationships' ? 'secondary' : 'primary'}/>
            </Tooltip>
          </ToggleButton>),
        ]}
      />
    )}
    </div>
  );
};
export default StixCoreRelationships;
