import { useState, useEffect, useRef } from 'react';
import { graphql } from 'react-relay';
import { QueryRenderer } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import { dayAgo } from '../../../../utils/Time';
import { buildFiltersAndOptionsForWidgets } from '../../../../utils/filters/filtersUtils';
import { computeStartEndDates } from '../../../../components/dashboard/dashboard-viz-utils';
import { useDashboardRefreshToken } from '../../../../components/dashboard/DashboardRefreshContext';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useEntityTranslation from '../../../../utils/hooks/useEntityTranslation';
import WidgetNumber from '../../../../components/dashboard/WidgetNumber';
import useDashboardViz from '../../../../components/dashboard/useDashboardViz';
import WidgetNoHostEntity from '../../../../components/dashboard/WidgetNoHostEntity';

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
}) => {
  const { t_i18n } = useFormatter();
  const { translateEntityType } = useEntityTranslation();

  const title = parameters.title ?? t_i18n('Draft workspaces number');
  const translatedTitle = translateEntityType(title);
  const { startDate, endDate } = computeStartEndDates(config);

  const refreshToken = useDashboardRefreshToken();
  const [localRefreshKey, setLocalRefreshKey] = useState(0);
  const prevRefreshTokenRef = useRef(refreshToken);
  useEffect(() => {
    if (prevRefreshTokenRef.current === refreshToken) return;
    prevRefreshTokenRef.current = refreshToken;
    setLocalRefreshKey((k) => k + 1);
  }, [refreshToken]);
  useEffect(() => {
    if (!refreshRate || refreshToken !== null) return () => {};
    const interval = setInterval(() => setLocalRefreshKey((k) => k + 1), refreshRate);
    return () => clearInterval(interval);
  }, [refreshRate, refreshToken]);

  const { resolvedDataSelection, isMissingHostEntity, isPreviewMode } = useDashboardViz({
    perspective: 'entities',
    dataSelection,
    host,
  });

  const selection = resolvedDataSelection[0];
  const dateAttribute = selection.date_attribute && selection.date_attribute.length > 0
    ? selection.date_attribute
    : 'created_at';
  const { filters } = buildFiltersAndOptionsForWidgets(
    selection.filters,
    { startDate, endDate, dateAttribute },
  );

  return (
    <WidgetContainer
      padding="medium"
      height={height}
      title={t_i18n('Draft workspaces number')}
      variant={variant}
      action={popover}
      showPreviewTag={isPreviewMode}
    >
      {isMissingHostEntity
        ? <WidgetNoHostEntity host={host} />
        : (
          <QueryRenderer
            key={localRefreshKey}
            query={draftsNumberQuery}
            variables={{
              dateAttribute,
              filters,
              startDate,
              endDate: dayAgo(),
            }}
            render={({ props }) => {
              if (props && props.draftWorkspacesNumber) {
                const { total, count } = props.draftWorkspacesNumber;
                return (
                  <WidgetNumber
                    entityType={entityType}
                    label={translatedTitle}
                    value={total}
                    diffLabel={t_i18n('24 hours')}
                    diffValue={total - count}
                  />
                );
              }
              if (props) {
                return <WidgetNoData />;
              }
              return <Loader variant={LoaderVariant.inElement} />;
            }}
          />
        )}
    </WidgetContainer>
  );
};

export default DraftsNumber;
