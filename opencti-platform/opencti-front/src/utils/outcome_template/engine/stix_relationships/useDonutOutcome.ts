import { stixRelationshipsDonutsDistributionQuery } from '@components/common/stix_relationships/StixRelationshipsDonut';
import { useTheme } from '@mui/styles';
import { ApexOptions } from 'apexcharts';
import { StixRelationshipsDonutDistributionQuery$data } from '@components/common/stix_relationships/__generated__/StixRelationshipsDonutDistributionQuery.graphql';
import { fetchQuery } from '../../../../relay/environment';
import type { Theme } from '../../../../components/Theme';
import useDistributionGraphData from '../../../hooks/useDistributionGraphData';
import { donutChartOptions } from '../../../Charts';
import chartDataURI from '../apexchartUtils';
import type { Widget } from '../../../widget/widget';

const useDonutOutcome = () => {
  const theme = useTheme<Theme>();
  const { buildWidgetLabelsOption } = useDistributionGraphData();

  const buildDonutOutcome = async (
    dataSelection: Pick<Widget['dataSelection'][0], 'date_attribute' | 'filters' | 'number' | 'columns' | 'attribute' | 'isTo' | 'dynamicTo' | 'dynamicFrom'>,
  ) => {
    const finalField = dataSelection.attribute || 'entity_type';
    const variables = {
      field: finalField,
      operation: 'count',
      dateAttribute: dataSelection.date_attribute ?? 'created_at',
      limit: dataSelection.number ?? 10,
      filters: dataSelection.filters,
      isTo: dataSelection.isTo,
      dynamicFrom: dataSelection.dynamicFrom,
      dynamicTo: dataSelection.dynamicTo,
    };
    const { stixRelationshipsDistribution: data } = await fetchQuery(
      stixRelationshipsDonutsDistributionQuery,
      variables,
    ).toPromise() as StixRelationshipsDonutDistributionQuery$data;

    if (!data) return '';

    const chartData = data.map((n) => n?.value);
    const labels = buildWidgetLabelsOption(data, finalField);
    let chartColors: string[] = [];
    if (data.at(0)?.entity?.color) {
      chartColors = data.map((n) => (theme.palette.mode === 'light' && n?.entity?.color === '#ffffff'
        ? '#000000'
        : n?.entity?.color ?? '#000000'));
    }
    if (data.at(0)?.entity?.x_opencti_color) {
      chartColors = data.map((n) => (theme.palette.mode === 'light' && n?.entity?.x_opencti_color === '#ffffff'
        ? '#000000'
        : n?.entity?.x_opencti_color ?? '#000000'));
    }
    if (data.at(0)?.entity?.template?.color) {
      chartColors = data.map((n) => (theme.palette.mode === 'light' && n?.entity?.template?.color === '#ffffff'
        ? '#000000'
        : n?.entity?.template?.color ?? '#000000'));
    }

    const chartOptions = {
      series: chartData,
      ...donutChartOptions(theme, labels, 'bottom', false, chartColors),
    };
    const dataURI = await chartDataURI(chartOptions as ApexOptions);
    return `<img src="${dataURI}" />`;
  };

  return { buildDonutOutcome };
};

export default useDonutOutcome;
