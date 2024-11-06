import { stixRelationshipsDonutsDistributionQuery } from '@components/common/stix_relationships/StixRelationshipsDonut';
import { useTheme } from '@mui/styles';
import { ApexOptions } from 'apexcharts';
import { StixRelationshipsDonutDistributionQuery$data } from '@components/common/stix_relationships/__generated__/StixRelationshipsDonutDistributionQuery.graphql';
import { useBuildFiltersForTemplateWidgets } from '../../../filters/filtersUtils';
import type { WidgetFromBackend } from '../../../widget/widget';
import { fetchQuery } from '../../../../relay/environment';
import type { Theme } from '../../../../components/Theme';
import useDistributionGraphData from '../../../hooks/useDistributionGraphData';
import { donutChartOptions } from '../../../Charts';
import chartDataURI from '../apexchartUtils';

const useDonutOutcome = () => {
  const theme = useTheme<Theme>();
  const { buildWidgetLabelsOption } = useDistributionGraphData();
  const { buildFiltersForTemplateWidgets } = useBuildFiltersForTemplateWidgets();

  const buildDonutOutcome = async (
    containerId: string,
    widget: WidgetFromBackend,
    maxContentMarkings: string[],
  ) => {
    const [selection] = widget.dataSelection;

    const filters = buildFiltersForTemplateWidgets(containerId, selection.filters, maxContentMarkings);
    const finalField = selection.attribute || 'entity_type';
    const variables = {
      field: finalField,
      operation: 'count',
      dateAttribute: selection.date_attribute ?? 'created_at',
      limit: selection.number ?? 10,
      filters,
      isTo: selection.isTo,
      dynamicFrom: selection.dynamicFrom,
      dynamicTo: selection.dynamicTo,
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
