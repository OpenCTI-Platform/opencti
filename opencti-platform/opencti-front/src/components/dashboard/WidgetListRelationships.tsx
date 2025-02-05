import React, { useMemo } from 'react';
import { WidgetColumn } from 'src/utils/widget/widget';
import { DataTableProps, DataTableVariant } from '../dataGrid/dataTableTypes';
import ItemIcon from '../ItemIcon';
import DataTableWithoutFragment from '../dataGrid/DataTableWithoutFragment';
import { computeLink } from '../../utils/Entity';

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
  const buildColumns = useMemo((): DataTableProps['dataColumns'] => {
    const columnKeys = columns.map((column) => column.attribute).filter((key) => key !== null);
    const iconWidth = 3;
    const percentWidth = (100 - iconWidth) / (columns.length ?? 1);

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
      label: ' ',
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      render: (stixRelationship: any) => (
        <ItemIcon
          type={stixRelationship.is_inferred ? 'autofix' : stixRelationship.entity_type}
          color="primary"
        />
      ),
    };
    return { icon: iconColumn, ...newColumns };
  }, [columns]);

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const getRedirectionLink = (stixRelationship: any) => {
    const remoteNode = stixRelationship.from ?? stixRelationship.to;
    return !publicWidget && remoteNode ? computeLink(remoteNode) : '';
  };

  return (
    <div style={{ width: '100%' }}>
      <DataTableWithoutFragment
        dataColumns={buildColumns}
        storageKey={widgetId}
        data={data.map(({ node }) => node)}
        globalCount={data.length}
        variant={DataTableVariant.widget}
        useComputeLink={getRedirectionLink}
        pageSize='50'
        disableNavigation={publicWidget}
        rootRef={rootRef}
      />
    </div>
  );
};

WidgetListRelationships.displayName = 'WidgetListRelationships';

export default WidgetListRelationships;
