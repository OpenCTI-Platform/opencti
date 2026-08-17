import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import { dayAgo } from '../../../../utils/Time';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetNumber from '../../../../components/dashboard/WidgetNumber';
import useDashboardViz from '../../../../components/dashboard/useDashboardViz';
import WidgetRenderContent from '../../../../components/dashboard/WidgetRenderContent';
import type { Widget, WidgetDataSelection, WidgetHost } from '../../../../utils/widget/widget';
import { StixCoreObjectsNumberNumberSeriesQuery } from './__generated__/StixCoreObjectsNumberNumberSeriesQuery.graphql';
import type { DashboardConfig } from '../../../../components/dashboard/dashboard-types';
import { computeWidgetFiltersForSelection } from '../../../../components/dashboard/dashboardVizUtils';
import { ReactNode } from 'react';
import { useGetNumberWidgetTitle } from 'src/utils/widget/widgetUtils';

const stixCoreObjectsNumberNumberQuery = graphql`
    query StixCoreObjectsNumberNumberSeriesQuery(
        $dateAttribute: String
        $types: [String]
        $startDate: DateTime
        $endDate: DateTime
        $onlyInferred: Boolean
        $filters: FilterGroup
        $search: String
    ) {
        stixCoreObjectsNumber(
            dateAttribute: $dateAttribute
            types: $types
            startDate: $startDate
            endDate: $endDate
            onlyInferred: $onlyInferred
            filters: $filters
            search: $search
        ) {
            total
            count
        }
    }
`;

interface StixCoreObjectsNumberComponentProps {
  queryRef: PreloadedQuery<StixCoreObjectsNumberNumberSeriesQuery>;
  entityType?: string;
  label: string;
}

const StixCoreObjectsNumberComponent = ({
  queryRef,
  entityType,
  label,
}: StixCoreObjectsNumberComponentProps) => {
  const data = usePreloadedQuery(stixCoreObjectsNumberNumberQuery, queryRef);
  const result = data?.stixCoreObjectsNumber;
  if (!result) {
    return <WidgetNoData />;
  }

  return (
    <WidgetNumber
      entityType={entityType}
      label={label}
      value={result.total}
      diffLabel="24 hours"
      diffValue={result.total - result.count}
    />
  );
};

interface StixCoreObjectsNumberProps {
  dataSelection: Widget['dataSelection'];
  parameters: { title?: string };
  entityType?: string;
  popover?: ReactNode;
  variant?: string;
  height?: number;
  host?: WidgetHost;
  config: DashboardConfig;
  refreshRate?: number | null;
}

const DATA_SELECTION_TYPES = ['Stix-Core-Object'];

const buildQueryVariables = (
  resolvedDataSelection: WidgetDataSelection[],
  config: DashboardConfig,
) => {
  const selection = resolvedDataSelection[0];
  const { startDate, dateAttribute, filters } = computeWidgetFiltersForSelection(selection, config);
  return {
    types: DATA_SELECTION_TYPES,
    dateAttribute,
    filters,
    startDate,
    endDate: dayAgo(),
  };
};

const StixCoreObjectsNumber = ({
  dataSelection,
  parameters = {},
  entityType,
  popover,
  variant,
  height,
  config,
  refreshRate = null,
  host,
}: StixCoreObjectsNumberProps) => {
  const { t_i18n } = useFormatter();
  const DEFAULT_TITLE = t_i18n('Entities number');

  const translatedNumberLabel = useGetNumberWidgetTitle(parameters, DEFAULT_TITLE);

  const { isMissingHostEntity, isMissingSavedFilters, isPreviewMode, queryRef } = useDashboardViz<StixCoreObjectsNumberNumberSeriesQuery>({
    perspective: 'entities',
    dataSelection,
    host,
    refreshRate,
    query: stixCoreObjectsNumberNumberQuery,
    buildQueryVariables,
    config,
  });

  return (
    <WidgetContainer
      padding="medium"
      height={height}
      title={DEFAULT_TITLE}
      variant={variant}
      action={popover}
      showPreviewTag={isPreviewMode}
    >
      <div style={{ height: '100%' }}>
        <WidgetRenderContent
          isMissingHostEntity={isMissingHostEntity}
          isMissingSavedFilters={isMissingSavedFilters}
          queryRef={queryRef}
          host={host}
        >
          <StixCoreObjectsNumberComponent
            queryRef={queryRef!}
            entityType={entityType}
            label={translatedNumberLabel}
          />
        </WidgetRenderContent>
      </div>
    </WidgetContainer>
  );
};

export default StixCoreObjectsNumber;
