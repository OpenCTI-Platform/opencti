import { CSSProperties, ReactNode, useEffect, useRef, useState } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import { dayAgo } from '../../../../utils/Time';
import { buildFiltersAndOptionsForWidgets, normalizeFilterGroupForBackend } from '../../../../utils/filters/filtersUtils';
import { computeStartEndDates } from '../../../../components/dashboard/dashboardVizUtils';
import type { DashboardConfig } from '../../../../components/dashboard/dashboard-types';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetNumber from '../../../../components/dashboard/WidgetNumber';
import useDashboardViz from '../../../../components/dashboard/useDashboardViz';
import WidgetRenderContent from '../../../../components/dashboard/WidgetRenderContent';
import type { WidgetDataSelection, WidgetHost, WidgetParameters } from '../../../../utils/widget/widget';
import { DraftsNumberQuery } from './__generated__/DraftsNumberQuery.graphql';
import { useGetNumberWidgetTitle } from 'src/utils/widget/widgetUtils';

const draftsNumberQuery = graphql`
  query DraftsNumberQuery(
    $dateAttribute: String
    $startDate: DateTime
    $endDate: DateTime
    $filters: FilterGroup
    $search: String
  ) {
    draftWorkspacesNumber(
      dateAttribute: $dateAttribute
      startDate: $startDate
      endDate: $endDate
      filters: $filters
      search: $search
    ) {
      total
      count
    }
  }
`;

const buildQueryVariables = (
  resolvedDataSelection: WidgetDataSelection[],
  config: DashboardConfig,
): DraftsNumberQuery['variables'] => {
  const selection = resolvedDataSelection[0];
  const { startDate } = computeStartEndDates(config);
  const dateAttribute = selection.date_attribute?.length
    ? selection.date_attribute
    : 'created_at';
  const { filters } = buildFiltersAndOptionsForWidgets(
    selection.filters,
    { startDate, dateAttribute },
  );
  return {
    dateAttribute,
    filters: normalizeFilterGroupForBackend(filters),
    startDate,
    endDate: dayAgo(),
  };
};

interface DraftsNumberComponentProps {
  queryRef: PreloadedQuery<DraftsNumberQuery>;
  entityType?: string;
  label: string;
}

const DraftsNumberComponent = ({
  queryRef,
  entityType,
  label,
}: DraftsNumberComponentProps) => {
  const { t_i18n } = useFormatter();
  const data = usePreloadedQuery(draftsNumberQuery, queryRef);

  if (!data?.draftWorkspacesNumber) {
    return <WidgetNoData />;
  }

  const { total, count } = data.draftWorkspacesNumber;

  return (
    <WidgetNumber
      entityType={entityType}
      label={label}
      value={total}
      diffLabel={t_i18n('24 hours')}
      diffValue={total - count}
    />
  );
};

interface DraftsNumberProps {
  config: DashboardConfig;
  refreshRate?: number | null;
  dataSelection: WidgetDataSelection[];
  parameters?: WidgetParameters;
  entityType?: string;
  popover?: ReactNode;
  variant?: string;
  height?: CSSProperties['height'];
  host?: WidgetHost;
}

const DraftsNumber = ({
  config,
  refreshRate = null,
  dataSelection,
  parameters = {},
  entityType,
  popover,
  variant,
  height,
  host,
}: DraftsNumberProps) => {
  const { t_i18n } = useFormatter();

  const DEFAULT_TITLE = t_i18n('Draft workspaces number');
  const translatedNumberLabel = useGetNumberWidgetTitle(parameters, DEFAULT_TITLE);

  const { isMissingHostEntity, isMissingSavedFilters, isPreviewMode, queryRef } = useDashboardViz<DraftsNumberQuery>({
    perspective: 'entities',
    dataSelection,
    host,
    refreshRate,
    query: draftsNumberQuery,
    config,
    buildQueryVariables,
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
      <WidgetRenderContent
        isMissingHostEntity={isMissingHostEntity}
        isMissingSavedFilters={isMissingSavedFilters}
        queryRef={queryRef}
        host={host}
      >
        <DraftsNumberComponent
          queryRef={queryRef!}
          entityType={entityType}
          label={translatedNumberLabel}
        />
      </WidgetRenderContent>
    </WidgetContainer>
  );
};

export default DraftsNumber;
