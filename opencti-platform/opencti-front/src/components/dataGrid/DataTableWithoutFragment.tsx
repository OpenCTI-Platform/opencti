import React from 'react';
import type { DataTableProps } from './dataTableTypes';
import { DataTableVariant } from './dataTableTypes';
import { useComputeLink, useDataCellHelpers, useDataTableToggle } from './dataTableHooks';
import DataTableComponent from './components/DataTableComponent';
import { useFormatter } from '../i18n';

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
| 'pageSize'
| 'variant'> & {
  data: unknown,
  globalCount: number
};

const DataTableWithoutFragment = (props: OCTIDataTableProps) => {
  const formatter = useFormatter();

  const {
    data,
    variant = DataTableVariant.default,
    storageKey,
  } = props;

  return (
    <DataTableComponent
      {...props}
      useDataTable={() => ({ data })}
      useLineData={(line) => line}
      dataQueryArgs={(line: never) => line}
      formatter={formatter}
      resolvePath={(a) => a}
      onAddFilter={() => {}}
      useDataTableToggle={useDataTableToggle(storageKey)}
      initialValues={{}}
      useComputeLink={useComputeLink}
      useDataCellHelpers={useDataCellHelpers({}, variant)}
      variant={variant}
    />
  );
};

export default DataTableWithoutFragment;
