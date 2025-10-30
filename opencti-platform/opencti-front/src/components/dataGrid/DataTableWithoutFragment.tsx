import React from 'react';
import DataTableToolBar from '@components/data/DataTableToolBar';
import { useTheme } from '@mui/styles';
import type { DataTableProps } from './dataTableTypes';
import DataTableComponent from './components/DataTableComponent';
import type { Theme } from '../Theme';
import { useDataTableContext } from './components/DataTableContext';

type OCTIDataTableProps = Pick<DataTableProps, 'dataColumns'
| 'storageKey'
| 'rootRef'
| 'actions'
| 'icon'
| 'disableNavigation'
| 'disableLineSelection'
| 'disableToolBar'
| 'removeSelectAll'
| 'selectOnLineClick'
| 'filtersComponent'
| 'getComputeLink'
| 'pageSize'
| 'hideHeaders'
| 'onLineClick'
| 'isLocalStorageEnabled'
| 'variant'> & {
  data: unknown,
  globalCount: number
};

const DataTableWithoutFragmentInternalToolbar = ({ taskScope }: { taskScope: string }) => {
  const theme = useTheme<Theme>();

  const {
    useDataTableToggle: {
      selectedElements,
      deSelectedElements,
      numberOfSelectedElements,
      selectAll,
      handleClearSelectedElements,
    },
  } = useDataTableContext();

  return (
    <div
      style={{
        background: theme.palette.background.accent,
        flex: 1,
      }}
    >
      <DataTableToolBar
        selectedElements={selectedElements}
        deSelectedElements={deSelectedElements}
        numberOfSelectedElements={numberOfSelectedElements}
        selectAll={selectAll}
        types={['Stix-Core-Object']}
        handleClearSelectedElements={handleClearSelectedElements}
        taskScope={taskScope}
      />
    </div>
  );
};

const DataTableWithoutFragment = (props: OCTIDataTableProps & {
  taskScope?: string
}) => {
  const { data, taskScope } = props;

  return (
    <DataTableComponent
      {...props}
      data={data}
      useLineData={(line) => line}
      dataQueryArgs={(line: never) => line}
      resolvePath={(a) => a}
      initialValues={{}}
      disableLineSelection={!taskScope}
      dataTableToolBarComponent={taskScope
        ? <DataTableWithoutFragmentInternalToolbar taskScope={taskScope} />
        : undefined
      }
    />
  );
};

export default DataTableWithoutFragment;
