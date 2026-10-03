import React, { ReactNode } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { ApexOptions } from 'apexcharts';
import { useTheme } from '@mui/styles';
import Chart from '@components/common/charts/Chart';
import { useFormatter } from '../../../../components/i18n';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import WidgetRenderContent from '../../../../components/dashboard/WidgetRenderContent';
import useDashboardViz from '../../../../components/dashboard/useDashboardViz';
import type { DashboardConfig } from '../../../../components/dashboard/dashboard-types';
import type { Theme } from '../../../../components/Theme';
import { verticalBarsChartOptions } from '../../../../utils/Charts';
import { simpleNumberFormat } from '../../../../utils/Number';
import type { Widget, WidgetDataSelection, WidgetHost, WidgetParameters, WidgetPerspective } from '../../../../utils/widget/widget';
import { FRESHNESS_BUCKET_LABELS } from './provenanceUtils';
import { buildProvenanceWidgetVariables } from './provenanceWidgetUtils';
import { ProvenanceFreshnessWidgetQuery } from './__generated__/ProvenanceFreshnessWidgetQuery.graphql';

const provenanceFreshnessWidgetQuery = graphql`
  query ProvenanceFreshnessWidgetQuery($types: [String!], $filters: FilterGroup) {
    provenanceFreshnessDistribution(types: $types, filters: $filters) {
      label
      value
    }
  }
`;

const ProvenanceFreshnessWidgetComponent = ({ queryRef }: { queryRef: PreloadedQuery<ProvenanceFreshnessWidgetQuery> }) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const { provenanceFreshnessDistribution } = usePreloadedQuery(provenanceFreshnessWidgetQuery, queryRef);
  if (provenanceFreshnessDistribution.every((entry) => entry.value === 0)) {
    return <WidgetNoData />;
  }
  return (
    <div data-testid="provenance-freshness-widget" style={{ height: '100%' }}>
      <Chart
        options={verticalBarsChartOptions(theme, (value: string) => value, simpleNumberFormat, true) as ApexOptions}
        series={[{
          name: t_i18n('Elements'),
          data: provenanceFreshnessDistribution.map((entry) => ({ x: t_i18n(FRESHNESS_BUCKET_LABELS[entry.label] ?? entry.label), y: entry.value })),
        }]}
        type="bar"
        width="100%"
        height="100%"
      />
    </div>
  );
};

interface ProvenanceFreshnessWidgetProps {
  perspective: WidgetPerspective;
  dataSelection: Widget['dataSelection'];
  parameters?: WidgetParameters | null;
  variant?: string;
  height?: number;
  popover?: ReactNode;
  host?: WidgetHost;
  config: DashboardConfig;
  refreshRate?: number | null;
}

/**
 * Widget of the catalog: knowledge per number of days since its last assertion by any source.
 */
const ProvenanceFreshnessWidget = ({
  perspective,
  dataSelection,
  parameters,
  variant,
  height,
  popover,
  host,
  config,
  refreshRate = null,
}: ProvenanceFreshnessWidgetProps) => {
  const { t_i18n } = useFormatter();
  const { resolvedDataSelection, isMissingHostEntity, isMissingSavedFilters, isPreviewMode, queryRef } = useDashboardViz<ProvenanceFreshnessWidgetQuery>({
    perspective,
    dataSelection,
    host,
    refreshRate,
    query: provenanceFreshnessWidgetQuery,
    config,
    buildQueryVariables: (selection: WidgetDataSelection[], dashboardConfig: DashboardConfig) => buildProvenanceWidgetVariables(perspective, selection, dashboardConfig),
  });
  return (
    <WidgetContainer
      padding="small"
      height={height}
      title={parameters?.title ?? t_i18n('Freshness distribution')}
      variant={variant}
      action={popover}
      showPreviewTag={isPreviewMode}
    >
      <WidgetRenderContent
        isMissingHostEntity={isMissingHostEntity}
        isMissingSavedFilters={isMissingSavedFilters}
        queryRef={queryRef}
        host={host}
      >
        {resolvedDataSelection.length > 0 && <ProvenanceFreshnessWidgetComponent queryRef={queryRef!} />}
      </WidgetRenderContent>
    </WidgetContainer>
  );
};

export default ProvenanceFreshnessWidget;
