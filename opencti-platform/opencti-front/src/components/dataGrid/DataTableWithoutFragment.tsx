import React from 'react';
import type { DataTableProps } from './dataTableTypes';
import DataTableComponent from './components/DataTableComponent';

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

const DataTableWithoutFragment = (props: OCTIDataTableProps) => {
  const { data } = props;

  return (
    <DataTableComponent
      {...props}
      data={data}
      useLineData={(line) => line}
      dataQueryArgs={(line: never) => line}
      resolvePath={(a) => a}
      initialValues={{}}
      disableLineSelection={true}
    />
  );
};

export default DataTableWithoutFragment;
