import React from 'react';
import DataTableWithoutFragment from '../dataGrid/DataTableWithoutFragment';
import { DataTableProps, DataTableVariant } from '../dataGrid/dataTableTypes';

interface WidgetListCoreObjectsProps {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  data: any[]
  dateAttribute: string
  publicWidget?: boolean
  rootRef: DataTableProps['rootRef']
  widgetId: string
  pageSize: number
  sortBy?: string
}

const WidgetListCoreObjects = ({
  data,
  dateAttribute,
  publicWidget = false,
  rootRef,
  widgetId,
  pageSize,
  sortBy,
}: WidgetListCoreObjectsProps) => {
  const dataColumns = {
    entity_type: { percentWidth: 10, isSortable: false },
    value: { percentWidth: 20, isSortable: false },
    createdBy: { percentWidth: 15, isSortable: false },
    date: {
      id: 'date',
      isSortable: false,
      percentWidth: 15,
      label: 'Date',
      // eslint-disable-next-line @typescript-eslint/ban-ts-comment
      // @ts-ignore
      render: (({ [dateAttribute]: date }, { fsd }) => fsd(date)),
    },
    objectLabel: { percentWidth: 10, isSortable: false },
    x_opencti_workflow_id: { percentWidth: 15, isSortable: false },
    objectMarking: { percentWidth: 15, isSortable: false },
  };
  if (sortBy && !['entity_type', 'name', 'value', 'observable_value', 'createdBy', 'objectLabel', 'x_opencti_workflow_id', 'objectMarking'].includes(sortBy)) {
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore
    delete dataColumns.x_opencti_workflow_id;
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore
    dataColumns[sortBy] = { percentWidth: 15, isSortable: false };
  }
  return (
    <DataTableWithoutFragment
      dataColumns={dataColumns}
      storageKey={widgetId}
      data={data.map(({ node }) => node)}
      globalCount={data.length}
      variant={DataTableVariant.widget}
      pageSize={pageSize.toString()}
      disableNavigation={publicWidget}
      rootRef={rootRef}
    />
  );
};

WidgetListCoreObjects.displayName = 'WidgetListCoreObjects';

export default WidgetListCoreObjects;
