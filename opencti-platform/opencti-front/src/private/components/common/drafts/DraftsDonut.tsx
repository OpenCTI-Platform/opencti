import ApexCharts from 'apexcharts';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { CSSProperties, ReactNode, useState } from 'react';
import { useFormatter } from '../../../../components/i18n';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import WidgetDonut from '../../../../components/dashboard/WidgetDonut';
import { computeWidgetFiltersForSelection } from '../../../../components/dashboard/dashboardVizUtils';
import type { DashboardConfig } from '../../../../components/dashboard/dashboard-types';
import type { Widget, WidgetDataSelection, WidgetHost, WidgetParameters } from '../../../../utils/widget/widget';
import { DraftsDonutDistributionQuery } from './__generated__/DraftsDonutDistributionQuery.graphql';
import useDashboardViz from 'src/components/dashboard/useDashboardViz';
import WidgetRenderContent from 'src/components/dashboard/WidgetRenderContent';

const draftsDonutDistributionQuery = graphql`
  query DraftsDonutDistributionQuery(
    $field: String!
    $startDate: DateTime
    $endDate: DateTime
    $dateAttribute: String
    $operation: StatsOperation!
    $limit: Int
    $order: String
    $filters: FilterGroup
    $search: String
  ) {
    draftWorkspacesDistribution(
      field: $field
      startDate: $startDate
      endDate: $endDate
      dateAttribute: $dateAttribute
      operation: $operation
      limit: $limit
      order: $order
      filters: $filters
      search: $search
    ) {
      label
      value
      entity {
        ... on BasicObject {
          id
          entity_type
        }
        ... on StixObject {
          representative {
            main
          }
        }
        ... on Creator {
          name
        }
        ... on Group {
          name
        }
      }
    }
  }
`;

interface DraftsDonutComponentProps {
  queryRef: PreloadedQuery<DraftsDonutDistributionQuery>;
  dataSelection: Widget['dataSelection'];
  setChart: (chart: ApexCharts) => void;
}

const DraftsDonutComponent = ({
  queryRef,
  dataSelection,
  setChart,
}: DraftsDonutComponentProps) => {
  const { draftWorkspacesDistribution } = usePreloadedQuery(
    draftsDonutDistributionQuery,
    queryRef,
  );
  const selection = dataSelection[0];
  const data = draftWorkspacesDistribution ?? [];

  return data.length === 0
    ? <WidgetNoData />
    : (
        <WidgetDonut
          data={data}
          groupBy={selection.attribute ?? 'entity_type'}
          onMounted={setChart}
        />
      );
};

interface DraftsDonutProps {
  variant?: string;
  height?: CSSProperties['height'];
  config: DashboardConfig;
  refreshRate?: number | null;
  dataSelection: WidgetDataSelection[];
  parameters?: WidgetParameters;
  popover?: ReactNode;
  host?: WidgetHost;
}

const buildQueryVariables = (
  resolvedDataSelection: WidgetDataSelection[],
  config: DashboardConfig,
): DraftsDonutDistributionQuery['variables'] => {
  const selection = resolvedDataSelection[0];
  const { dateAttribute, startDate, endDate, filters } = computeWidgetFiltersForSelection(selection, config);
  return {
    field: selection.attribute ?? 'entity_type',
    operation: 'count',
    startDate,
    endDate,
    dateAttribute,
    filters,
    limit: selection.number ?? 10,
  };
};

const DraftsDonut = ({
  variant,
  height,
  config,
  refreshRate = null,
  dataSelection,
  parameters = {},
  popover,
  host,
}: DraftsDonutProps) => {
  const { t_i18n } = useFormatter();
  const [chart, setChart] = useState<ApexCharts>();

  const { resolvedDataSelection, isMissingHostEntity, isMissingSavedFilters, isPreviewMode, queryRef } = useDashboardViz<DraftsDonutDistributionQuery>({
    perspective: 'entities',
    dataSelection,
    host,
    refreshRate,
    query: draftsDonutDistributionQuery,
    config,
    buildQueryVariables,
  });

  return (
    <WidgetContainer
      padding="small"
      height={height}
      title={parameters.title ?? t_i18n('Distribution of draft workspaces')}
      variant={variant}
      chart={chart}
      action={popover}
      showPreviewTag={isPreviewMode}
    >
      <WidgetRenderContent
        isMissingHostEntity={isMissingHostEntity}
        isMissingSavedFilters={isMissingSavedFilters}
        queryRef={queryRef}
        host={host}
      >
        <DraftsDonutComponent
          queryRef={queryRef!}
          dataSelection={resolvedDataSelection}
          setChart={setChart}
        />
      </WidgetRenderContent>
    </WidgetContainer>
  );
};

export default DraftsDonut;
