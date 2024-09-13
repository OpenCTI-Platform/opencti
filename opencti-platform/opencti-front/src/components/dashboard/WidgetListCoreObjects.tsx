import React from 'react';
import { v4 as uuid } from 'uuid';
import DataTableWithoutFragment from '../dataGrid/DataTableWithoutFragment';
import { DataTableProps, DataTableVariant } from '../dataGrid/dataTableTypes';

interface WidgetListCoreObjectsProps {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  data: any[]
  dateAttribute: string
  publicWidget?: boolean
  rootRef: DataTableProps['rootRef']
}

const WidgetListCoreObjects = ({
  data,
  dateAttribute,
  publicWidget = false,
  rootRef,
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
    storageKey={uuid()}
    data={data.map(({ node }) => node)}
    globalCount={data.length}
    variant={DataTableVariant.widget}
    disableNavigation={publicWidget}
    rootRef={rootRef}
  />
);

WidgetListCoreObjects.displayName = 'WidgetListCoreObjects';

export default WidgetListCoreObjects;
