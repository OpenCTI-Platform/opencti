import React, { FunctionComponent } from 'react';
import Grid from '@mui/material/Grid';
import type { WidgetColumn } from '../../../utils/widget/widget';
import type { WidgetColumnsLayout } from './WidgetCustomAttributesColumnsInput';
import WidgetCustomAttributesCard, { StixCoreObject } from './WidgetCustomAttributesCard';

interface WidgetCustomAttributesProps {
  data: StixCoreObject | null | undefined;
  columns: WidgetColumn[];
  layout?: WidgetColumnsLayout;
}

const WidgetCustomAttributes: FunctionComponent<WidgetCustomAttributesProps> = ({
  data,
  columns,
  layout = '1',
}) => {
  const col1 = layout === '2' ? columns.filter((_, i) => i % 2 === 0) : columns;
  const col2 = layout === '2' ? columns.filter((_, i) => i % 2 === 1) : [];

  return (
    <Grid container spacing={3}>
      <Grid item xs={layout === '2' ? 6 : 12}>
        {col1.map((column) => (
          <WidgetCustomAttributesCard
            key={column.attribute}
            column={column}
            data={data}
          />
        ))}
      </Grid>
      {layout === '2' && (
        <Grid item xs={6}>
          {col2.map((column) => (
            <WidgetCustomAttributesCard
              key={column.attribute}
              column={column}
              data={data}
            />
          ))}
        </Grid>
      )}
    </Grid>
  );
};

WidgetCustomAttributes.displayName = 'WidgetCustomAttributes';

export default WidgetCustomAttributes;
