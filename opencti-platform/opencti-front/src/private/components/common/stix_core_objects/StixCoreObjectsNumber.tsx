import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import { dayAgo } from '../../../../utils/Time';
import { buildFiltersAndOptionsForWidgets, normalizeFilterGroupForBackend } from '../../../../utils/filters/filtersUtils';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useEntityTranslation from '../../../../utils/hooks/useEntityTranslation';
import WidgetNumber from '../../../../components/dashboard/WidgetNumber';
import useDashboardViz from '../../../../components/dashboard/useDashboardViz';
import WidgetNoHostEntity from '../../../../components/dashboard/WidgetNoHostEntity';
import WidgetNoSavedFilters from 'src/components/dashboard/WidgetNoSavedFilters';
import type { Widget, WidgetDataSelection, WidgetHost } from '../../../../utils/widget/widget';
import { StixCoreObjectsNumberNumberSeriesQuery } from './__generated__/StixCoreObjectsNumberNumberSeriesQuery.graphql';
import type { DashboardConfig } from '../../../../components/dashboard/dashboard-types';
import { computeStartEndDates } from '../../../../components/dashboard/dashboardVizUtils';
import { ReactNode, Suspense } from 'react';

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
  const dateAttribute = selection.date_attribute && selection.date_attribute.length > 0
    ? selection.date_attribute
    : 'created_at';
  const { startDate, endDate } = computeStartEndDates(config);
  const { filters } = buildFiltersAndOptionsForWidgets(
    selection.filters,
    { startDate, endDate, dateAttribute },
  );
  return {
    types: DATA_SELECTION_TYPES,
    dateAttribute,
    filters: normalizeFilterGroupForBackend(filters),
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
  const { translateEntityType } = useEntityTranslation();

  const title = parameters.title ?? t_i18n('Entities number');
  const translatedTitle = translateEntityType(title);

  const { isMissingHostEntity, isMissingSavedFilters, isPreviewMode, queryRef } = useDashboardViz<StixCoreObjectsNumberNumberSeriesQuery>({
    perspective: 'entities',
    dataSelection,
    host,
    refreshRate,
    query: stixCoreObjectsNumberNumberQuery,
    buildQueryVariables,
    config,
  });

  const renderContent = () => {
    if (isMissingHostEntity) {
      return <WidgetNoHostEntity host={host} />;
    }

    if (isMissingSavedFilters) {
      return <WidgetNoSavedFilters />;
    }

    if (!queryRef) return null;

    return (
      <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
        <StixCoreObjectsNumberComponent
          queryRef={queryRef}
          entityType={entityType}
          label={translatedTitle}
        />
      </Suspense>
    );
  };

  return (
    <WidgetContainer
      padding="medium"
      height={height}
      title={t_i18n('Entities number')}
      variant={variant}
      action={popover}
      showPreviewTag={isPreviewMode}
    >
      <div style={{ height: '100%' }}>
        {renderContent()}
      </div>
    </WidgetContainer>
  );
};

export default StixCoreObjectsNumber;
