import Chart from '@components/common/charts/Chart';
import React from 'react';
import { useTheme } from '@mui/styles';
import { useNavigate } from 'react-router-dom-v5-compat';
import { ApexOptions } from 'apexcharts';
import { horizontalBarsChartOptions } from '../../utils/Charts';
import { simpleNumberFormat } from '../../utils/Number';
import type { Theme } from '../Theme';

interface WidgetHorizontalBarsProps {
  series: ApexAxisChartSeries
  distributed?: boolean
  withExport?: boolean
  readonly?: boolean
  redirectionUtils?: {
    id?: string
    entity_type?: string
  }[]
}

const WidgetHorizontalBars = ({
  series,
  distributed,
  withExport,
  readonly,
  redirectionUtils,
}: WidgetHorizontalBarsProps) => {
  const theme = useTheme<Theme>();
  const navigate = useNavigate();

  return (
    <Chart
      options={horizontalBarsChartOptions(
        theme,
        true,
        simpleNumberFormat,
        undefined,
        distributed,
        navigate,
        redirectionUtils,
      ) as ApexOptions}
      series={series}
      type="bar"
      width="100%"
      height="100%"
      withExportPopover={withExport}
      isReadOnly={readonly}
    />
  );
};

export default WidgetHorizontalBars;
