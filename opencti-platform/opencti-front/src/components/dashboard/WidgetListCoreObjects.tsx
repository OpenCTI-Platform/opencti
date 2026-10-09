import React, { useMemo } from 'react';
import DataTableWithoutFragment from '../dataGrid/DataTableWithoutFragment';
import { DataTableColumn, DataTableProps, DataTableVariant } from '../dataGrid/dataTableTypes';
import { defaultRender } from '../dataGrid/dataTableUtils';
import type { WidgetColumn } from '../../utils/widget/widget';
import { getCustomFieldRawValueByFieldName, isCustomFieldAttribute } from '../../utils/customFields';

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
          // Custom fields are not part of the DataTable column registry (they are
          // dynamic, per-deployment), so they need their own generic renderer reading
          // the entity's `customFieldValues` instead of relying on a registered one.
          const customFieldRender = isCustomFieldAttribute(attribute)
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            ? (node: any) => {
                const value = getCustomFieldRawValueByFieldName(node?.customFieldValues, attribute);
                return defaultRender(Array.isArray(value) ? value.join(', ') : value);
              }
            : undefined;
          acc[attribute] = {
            percentWidth,
            isSortable: false,
            ...(label ? { label } : {}),
            ...(customFieldRender ? { render: customFieldRender } : {}),
          };
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
