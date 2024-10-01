import React from 'react';
import DataTableToolBar from '@components/data/DataTableToolBar';
import { useTheme } from '@mui/styles';
import type { DataTableProps } from './dataTableTypes';
import { DataTableVariant } from './dataTableTypes';
import { useComputeLink, useDataCellHelpers, useDataTableLocalStorage, useDataTableToggle } from './dataTableHooks';
import DataTableComponent from './components/DataTableComponent';
import { useFormatter } from '../i18n';
import { numberFormat } from '../../utils/Number';
import { SELECT_COLUMN_SIZE } from './components/DataTableHeader';
import { FilterGroup } from '../../utils/filters/filtersHelpers-types';
import type { Theme } from '../Theme';
import ResetColumnsButton from './components/ResetColumnsButton';

type OCTIDataTableWithoutFragmentProps = Pick<DataTableProps, 'dataColumns'
| 'storageKey'
| 'rootRef'
| 'actions'
| 'disableNavigation'
| 'disableLineSelection'
| 'disableToolBar'
| 'disableSelectAll'
| 'selectOnLineClick'
| 'filtersComponent'
| 'pageSize'
| 'variant'> & {
  data: unknown,
  globalCount: number,
  allowBackgroundtasks: boolean,
  taskScope?: string,
  searchTerm?: string,
  toolbarFilters?: FilterGroup,
};

const DataTableWithoutFragment = (props: OCTIDataTableWithoutFragmentProps) => {
  const theme = useTheme<Theme>();
  const formatter = useFormatter();

  const {
    data,
    variant = DataTableVariant.default,
    globalCount,
    storageKey,
    allowBackgroundtasks,
    taskScope,
    searchTerm,
    toolbarFilters,
  } = props;

  const {
    selectedElements,
    deSelectedElements,
    numberOfSelectedElements,
    selectAll,
    handleClearSelectedElements,
  } = useDataTableToggle(storageKey);

  return (
    <DataTableComponent
      numberOfElements={numberFormat(globalCount)}
      useDataTable={() => ({ data })}
      useLineData={(line) => line}
      dataQueryArgs={(line: never) => line}
      formatter={formatter}
      resolvePath={(a) => a}
      useDataTableLocalStorage={useDataTableLocalStorage}
      useDataTableToggle={allowBackgroundtasks ? useDataTableToggle : () => ({})}
      initialValues={{}}
      useComputeLink={useComputeLink}
      useDataCellHelpers={useDataCellHelpers({}, variant)}
      variant={variant}
      {...props}
      filtersComponent={
        <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
          <div
            style={{
              border: '1px solid #ccc',
              borderRadius: '4px',
            }}
          >
            <ResetColumnsButton/>
          </div>
        </div>
      }
      dataTableToolBarComponent={allowBackgroundtasks ? (
        <div
          style={{
            background: theme.palette.background.default,
            width: `calc(( var(--header-table-size) - ${SELECT_COLUMN_SIZE} ) * 1px)`,
          }}
        >
          <DataTableToolBar
            selectedElements={selectedElements}
            deSelectedElements={deSelectedElements}
            numberOfSelectedElements={numberOfSelectedElements}
            selectAll={selectAll}
            search={searchTerm}
            filters={toolbarFilters}
            handleClearSelectedElements={handleClearSelectedElements}
            taskScope={taskScope}
          />
        </div>
      ) : undefined}
    />
  );
};

export default DataTableWithoutFragment;
