import Chart from '@components/common/charts/Chart';
import React from 'react';
import { useTheme } from '@mui/styles';
import { useNavigate } from 'react-router-dom';
import { ApexOptions } from 'apexcharts';
import { horizontalBarsChartOptions } from '../../utils/Charts';
import { simpleNumberFormat } from '../../utils/Number';
import type { Theme } from '../Theme';

interface WidgetHorizontalBarsProps {
  series: ApexAxisChartSeries
  distributed?: boolean
  stacked?: boolean
  total?: boolean
  legend?: boolean
  categories?: string[]
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
  stacked,
  total,
  legend,
  categories,
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
        simpleNumberFormat,
        distributed,
        navigate,
        redirectionUtils,
        stacked,
        total,
        categories,
        legend,
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
