import React from 'react';
import { useTheme } from '@mui/styles';
import DataTableWithoutFragmentToolBar from '@components/data/DataTableWithoutFragmentToolBar';
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

interface DataTableWithoutFragmentInternalToolBarProps {
  taskScope: string,
  dataIds: string[],
}

const DataTableWithoutFragmentInternalToolbar = ({ taskScope, dataIds }: DataTableWithoutFragmentInternalToolBarProps) => {
  const theme = useTheme<Theme>();

  const {
    useDataTableToggle: {
      selectedElements,
      deSelectedElements,
      selectAll,
      handleClearSelectedElements,
    },
  } = useDataTableContext();
  const selectedValues = selectAll
    ? dataIds.filter((v) => !Object.keys(deSelectedElements).includes(v))
    : Object.keys(selectedElements);

  return (
    <div
      style={{
        background: theme.palette.background.accent,
        flex: 1,
      }}
    >
      <DataTableWithoutFragmentToolBar
        selectedValues={selectedValues}
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

  const extractDataIds = () => {
    if (!Array.isArray(data)) return [];
    return data.map((d) => d?.id).filter((id): id is string => typeof id === 'string');
  };

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
        ? <DataTableWithoutFragmentInternalToolbar
            dataIds={extractDataIds()}
            taskScope={taskScope}
          />
        : undefined
      }
    />
  );
};

export default DataTableWithoutFragment;
