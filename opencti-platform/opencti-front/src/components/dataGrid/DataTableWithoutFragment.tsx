import React from 'react';
import type { DataTableProps } from './dataTableTypes';
import DataTableComponent from './components/DataTableComponent';

type OCTIDataTableProps = Pick<DataTableProps, 'dataColumns'
| 'storageKey'
| 'rootRef'
| 'actions'
| 'disableNavigation'
| 'disableLineSelection'
| 'disableToolBar'
| 'disableSelectAll'
| 'selectOnLineClick'
| 'filtersComponent'
| 'useComputeLink'
| 'pageSize'
| 'hideHeaders'
| 'onLineClick'
| 'variant'> & {
  data: unknown,
  globalCount: number
};

const DataTableWithoutFragment = (props: OCTIDataTableProps) => {
  const { data } = props;

  return (
    <DataTableComponent
      {...props}
      useDataTable={() => ({ data })}
      useLineData={(line) => line}
      dataQueryArgs={(line: never) => line}
      resolvePath={(a) => a}
      initialValues={{}}
      canToggleLine={false}
    />
  );
};

export default DataTableWithoutFragment;
