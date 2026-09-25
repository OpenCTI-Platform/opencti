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

export type DonutOutcome = {
  html: string;
  isEmpty: boolean;
};

const useDonutOutcome = () => {
  const theme = useTheme<Theme>();
  const { buildWidgetLabelsOption } = useDistributionGraphData();

  function buildDonutOutcome(
    dataSelection: Pick<Widget['dataSelection'][0], 'date_attribute' | 'filters' | 'number' | 'columns' | 'attribute' | 'isTo' | 'dynamicTo' | 'dynamicFrom'>,
    options: { includeMetadata: true },
  ): Promise<DonutOutcome>;
  function buildDonutOutcome(
    dataSelection: Pick<Widget['dataSelection'][0], 'date_attribute' | 'filters' | 'number' | 'columns' | 'attribute' | 'isTo' | 'dynamicTo' | 'dynamicFrom'>,
    options?: { includeMetadata?: boolean },
  ): Promise<string>;
  async function buildDonutOutcome(
    dataSelection: Pick<Widget['dataSelection'][0], 'date_attribute' | 'filters' | 'number' | 'columns' | 'attribute' | 'isTo' | 'dynamicTo' | 'dynamicFrom'>,
    options?: { includeMetadata?: boolean },
  ): Promise<string | DonutOutcome> {
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

    if (!data) {
      const emptyOutcome = { html: '', isEmpty: true };
      return options?.includeMetadata ? emptyOutcome : emptyOutcome.html;
    }

    const chartData = data.map((n) => n?.value);
    const isEmpty = !data.some((item) => (item?.value ?? 0) > 0);
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
    const outcome = {
      html: `<img src="${dataURI}" />`,
      isEmpty,
    };
    return options?.includeMetadata ? outcome : outcome.html;
  }

  return { buildDonutOutcome };
};

export default useDonutOutcome;
