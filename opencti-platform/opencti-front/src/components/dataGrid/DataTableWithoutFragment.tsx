import React from 'react';
import type { DataTableProps } from './dataTableTypes';
import { DataTableVariant } from './dataTableTypes';
import { useComputeLink, useDataCellHelpers, useDataTableLocalStorage } from './dataTableHooks';
import DataTableComponent from './components/DataTableComponent';
import { useFormatter } from '../i18n';
import { numberFormat } from '../../utils/Number';

type OCTIDataTableProps = Pick<DataTableProps, 'dataColumns'
| 'storageKey'
| 'rootRef'
| 'actions'
| 'disableNavigation'
| 'filtersComponent'
| 'variant'> & {
  data: unknown,
  globalCount: number
};

const DataTableWithoutFragment = (props: OCTIDataTableProps) => {
  const formatter = useFormatter();

  const {
    data,
    variant = DataTableVariant.default,
    globalCount,
  } = props;

  return (
    <DataTableComponent
      numberOfElements={numberFormat(globalCount)}
      useDataTable={() => ({ data })}
      useLineData={(line) => line}
      dataQueryArgs={(line: never) => line}
      formatter={formatter}
      resolvePath={(a) => a}
      useDataTableLocalStorage={useDataTableLocalStorage}
      useDataTableToggle={() => ({})}
      initialValues={{}}
      useComputeLink={useComputeLink}
      useDataCellHelpers={useDataCellHelpers({}, variant)}
      variant={variant}
      {...props}
    />
  );
};

export default DataTableWithoutFragment;
