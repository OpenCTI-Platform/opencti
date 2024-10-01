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
}

const WidgetListCoreObjects = ({
  data,
  dateAttribute,
  publicWidget = false,
  rootRef,
  widgetId,
  pageSize,
}: WidgetListCoreObjectsProps) => (
  <DataTableWithoutFragment
    dataColumns={{
      entity_type: { percentWidth: 10 },
      value: { percentWidth: 30 },
      date: {
        id: 'date',
        isSortable: false,
        percentWidth: 15,
        label: 'Date',
        render: (({ [dateAttribute]: date }, { fsd }) => fsd(date)),
      },
      objectLabel: { percentWidth: 15 },
      x_opencti_workflow_id: { percentWidth: 15 },
      objectMarking: { percentWidth: 15 },
    }}
    storageKey={widgetId}
    data={data.map(({ node }) => node)}
    globalCount={data.length}
    variant={DataTableVariant.widget}
    pageSize={pageSize.toString()}
    disableNavigation={publicWidget}
    rootRef={rootRef}
    allowBackgroundtasks={false}
  />
);

WidgetListCoreObjects.displayName = 'WidgetListCoreObjects';

export default WidgetListCoreObjects;
