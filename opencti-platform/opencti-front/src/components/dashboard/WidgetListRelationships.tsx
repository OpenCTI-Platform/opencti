import React, { useState, useEffect } from 'react';
import { DataTableProps, DataTableVariant } from 'src/components/dataGrid/dataTableTypes';
import { WidgetColumn } from 'src/utils/widget/widget';
import ItemIcon from '../ItemIcon';
import DataTableWithoutFragment from '../dataGrid/DataTableWithoutFragment';

interface WidgetListRelationshipsProps {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  data: any[]
  publicWidget?: boolean
  widgetId: string;
  rootRef: DataTableProps['rootRef'],
  columns: WidgetColumn[]
}

const WidgetListRelationships = ({
  data,
  publicWidget = false,
  widgetId,
  rootRef,
  columns,
}: WidgetListRelationshipsProps) => {
  const [currentColumns, setCurrentColumns] = useState<DataTableProps['dataColumns']>();

  useEffect(() => {
    const columnKeys = columns.map((column) => column.attribute).filter((key) => key !== null);
    const iconWidth = 3;
    const percentWidth = (100 - iconWidth) / (columns?.length ?? 1);

    const newColumns = (
      columnKeys.reduce<DataTableProps['dataColumns']>(
        (acc, current) => ({
          ...acc,
          [current]: { percentWidth, isSortable: false },
        }),
        {},
      )
    ) as DataTableProps['dataColumns'];

    const iconColumn = {
      percentWidth: iconWidth,
      isSortable: false,
      label: ' ',
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      render: (stixRelationship: any) => (
        <ItemIcon
          type={stixRelationship.entity_type}
          color="primary"
        />
      ),
    };
    setCurrentColumns({ icon: iconColumn, ...newColumns });
  }, [columns]);

  if (!currentColumns) return null;
  return (
    <div style={{ width: '100%' }}>
      <DataTableWithoutFragment
        dataColumns={currentColumns}
        storageKey={widgetId}
        data={data.map(({ node }) => node)}
        globalCount={data.length}
        variant={DataTableVariant.widget}
        pageSize='50'
        disableNavigation={publicWidget}
        rootRef={rootRef}
        isLocalStorageEnabled={false}
      />
    </div>
  );
};

WidgetListRelationships.displayName = 'WidgetListRelationships';

export default WidgetListRelationships;
