import React, { useMemo } from 'react';
import DataTableWithoutFragment from '../dataGrid/DataTableWithoutFragment';
import { DataTableColumn, DataTableProps, DataTableVariant } from '../dataGrid/dataTableTypes';
import type { WidgetColumn } from '../../utils/widget/widget';

interface WidgetListCoreObjectsProps {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  data: readonly any[];
  publicWidget?: boolean;
  rootRef: DataTableProps['rootRef'];
  widgetId: string;
  pageSize: number;
  columns: WidgetColumn[];
}

const WidgetListCoreObjects = ({
  data,
  publicWidget = false,
  rootRef,
  widgetId,
  pageSize,
  columns,
}: WidgetListCoreObjectsProps) => {
  const buildColumns = useMemo((): DataTableProps['dataColumns'] => {
    const percentWidth = (100) / (columns.length ?? 1);

    return columns
      .reduce<Record<string, Partial<DataTableColumn>>>(
        (acc, { attribute, label }) => {
          if (!attribute) {
            return acc;
          }
          // Custom fields (x_opencti_cf_*) are dynamic and not in defaultColumnsMap,
          // so we provide a simple text renderer to display their raw value.
          if (attribute.startsWith('x_opencti_cf_')) {
            acc[attribute] = {
              percentWidth,
              isSortable: false,
              ...(label ? { label } : {}),
              // eslint-disable-next-line @typescript-eslint/no-explicit-any
              render: (rowData: any) => {
                const val = rowData[attribute];
                if (val === null || val === undefined || val === '') {
                  return <span>-</span>;
                }
                return (
                  <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {String(val)}
                  </span>
                );
              },
            };
          } else {
            acc[attribute] = { percentWidth, isSortable: false, ...(label ? { label } : {}) };
          }
          return acc;
        },
        {},
      );
  }, [columns]);

  return (
    <DataTableWithoutFragment
      dataColumns={buildColumns}
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
