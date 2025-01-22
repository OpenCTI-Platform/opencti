import React, { useCallback } from 'react';
import DataTableWithoutFragment from '../dataGrid/DataTableWithoutFragment';
import { DataTableProps, DataTableVariant } from '../dataGrid/dataTableTypes';
import type { WidgetColumn } from '../../utils/widget/widget';

interface WidgetListCoreObjectsProps {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  data: any[]
  publicWidget?: boolean
  rootRef: DataTableProps['rootRef']
  widgetId: string
  pageSize: number
  sortBy?: string
  columns: WidgetColumn[]
}

const WidgetListCoreObjects = ({
  data,
  publicWidget = false,
  rootRef,
  widgetId,
  pageSize,
  // TODO handle sortBy ?
  // sortBy,
  columns,
}: WidgetListCoreObjectsProps) => {
  const buildColumns = useCallback((): DataTableProps['dataColumns'] => {
    const columnKeys = columns.map((column) => column.attribute).filter((key) => key !== null);
    const percentWidth = (100) / (columns.length ?? 1);
    // if (sortBy && !['entity_type', 'name', 'value', 'observable_value', 'createdBy', 'objectLabel', 'x_opencti_workflow_id', 'objectMarking'].includes(sortBy)) {
    //   // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    //   // @ts-ignore
    //   delete dataColumns.x_opencti_workflow_id;
    //   // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    //   // @ts-ignore
    //   dataColumns[sortBy] = { percentWidth: 15, isSortable: false };
    // }
    return (
      columnKeys.reduce<DataTableProps['dataColumns']>(
        (acc, current) => ({
          ...acc,
          [current]: { percentWidth, isSortable: false },
        }),
        {},
      )
    ) as DataTableProps['dataColumns'];
  }, [columns]);

  return (
    <DataTableWithoutFragment
      dataColumns={buildColumns()}
      storageKey={widgetId}
      data={data.map(({ node }) => node)}
      globalCount={data.length}
      variant={DataTableVariant.widget}
      pageSize={pageSize.toString()}
      disableNavigation={publicWidget}
      rootRef={rootRef}
      isLocalStorageEnabled={false}
    />
  );
};

WidgetListCoreObjects.displayName = 'WidgetListCoreObjects';

export default WidgetListCoreObjects;
