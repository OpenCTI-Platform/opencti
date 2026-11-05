import React, { useEffect, useMemo, useState } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { useNavigate, useParams } from 'react-router';
import ReactGridLayout, { useContainerWidth } from 'react-grid-layout';
import { ErrorBoundary } from '@components/Error';
import Loader, { LoaderVariant } from '../../components/Loader';
import { PublicDashboardQuery } from './__generated__/PublicDashboardQuery.graphql';
import useQueryLoading from '../../utils/hooks/useQueryLoading';
import { fromB64 } from '../../utils/String';
import usePublicDashboardWidgets from './dashboard/usePublicDashboardWidgets';
import PublicTopBar from './PublicTopBar';
import PublicDashboardHeader from './dashboard/PublicDashboardHeader';
import { useFormatter } from '../../components/i18n';
import type { DashboardManifest } from '../../components/dashboard/dashboard-types';
import {
  applyPublishedTimeRangeChange,
  isSamePublishedTimeRange,
  pickPublishedTimeRange,
  type PublishedTimeRange,
} from '@components/workspaces/dashboards/public_dashboards/public-dashboard-utils';
import useDashboardRefresh from '../../components/dashboard/useDashboardRefresh';
import DashboardRefreshControl from '../../components/dashboard/DashboardRefreshControl';
import { DashboardRefreshProvider } from '../../components/dashboard/DashboardRefreshContext';

const publicDashboardQuery = graphql`
  query PublicDashboardQuery($uri_key: String!) {
    publicDashboardByUriKey(uri_key: $uri_key) {
      name
      enabled
      public_manifest
    }
  }
`;

interface PublicDashboardComponentProps {
  queryRef: PreloadedQuery<PublicDashboardQuery>;
  uriKey: string;
}

const PublicDashboardComponent = ({
  queryRef,
  uriKey,
}: PublicDashboardComponentProps) => {
  const navigate = useNavigate();
  const { width, containerRef } = useContainerWidth();
  const { t_i18n } = useFormatter();

  const { publicDashboardByUriKey } = usePreloadedQuery(publicDashboardQuery, queryRef);
  const manifest = publicDashboardByUriKey?.public_manifest;
  const parsedManifest: DashboardManifest = JSON.parse(manifest ? fromB64(manifest) : '{}');
  const { widgets, config } = parsedManifest;
  const initialRefreshRateSeconds = config?.refresh_interval ?? 0;

  const {
    localRefreshRateSeconds,
    refreshToken,
    isAutoRefreshing,
    handleManualRefresh,
    handleRefreshRateChange,
  } = useDashboardRefresh({
    initialRefreshRateSeconds,
  });

  useEffect(() => {
    if (publicDashboardByUriKey === null || !publicDashboardByUriKey?.enabled) {
      navigate('/');
    }
  }, [publicDashboardByUriKey, navigate]);

  // The published range is the default; a visitor may pick another one when the author allowed viewers to edit the
  // time filters. Local to the page: nothing is written anywhere.
  const canEditTimeFilters = config?.allowViewersToEditTimeFilters === true;
  const publishedRange = useMemo(() => pickPublishedTimeRange(config), [config?.startDate, config?.endDate, config?.relativeDate]);
  const [localRange, setLocalRange] = useState<PublishedTimeRange | null>(null);
  const effectiveRange = canEditTimeFilters && localRange ? localRange : publishedRange;
  const effectiveConfig = useMemo(
    () => (config ? { ...config, ...effectiveRange } : config),
    [config, effectiveRange.startDate, effectiveRange.endDate, effectiveRange.relativeDate],
  );
  const changeRange = (type: 'startDate' | 'endDate' | 'relativeDate', value: string | null) => {
    if (!canEditTimeFilters) return;
    const next = applyPublishedTimeRangeChange(effectiveRange, type, value);
    setLocalRange(isSamePublishedTimeRange(next, publishedRange) ? null : next);
  };

  const {
    entityWidget,
    relationshipWidget,
    rawWidget,
    auditWidget,
  } = usePublicDashboardWidgets(uriKey, effectiveConfig);

  const onChangeRelativeDate = (value: string) => changeRange('relativeDate', value);
  const onChangeStartDate = (value: string | null) => changeRange('startDate', value);
  const onChangeEndDate = (value: string | null) => changeRange('endDate', value);

  if (!publicDashboardByUriKey || !config) {
    return null;
  }

  const widgetsArray = Object.values(widgets ?? {});
  const widgetsWithLayout = widgetsArray.filter((w) => w.layout);

  return (
    <>
      <PublicTopBar title={t_i18n('Public dashboard')} />
      <DashboardRefreshProvider refreshToken={refreshToken}>
        <PublicDashboardHeader
          title={publicDashboardByUriKey?.name ?? ''}
          manifestConfig={effectiveConfig ?? config}
          editable={canEditTimeFilters}
          onReset={canEditTimeFilters && localRange ? () => setLocalRange(null) : undefined}
          onChangeRelativeDate={onChangeRelativeDate}
          onChangeStartDate={onChangeStartDate}
          onChangeEndDate={onChangeEndDate}
          actions={(
            <DashboardRefreshControl
              onRefresh={handleManualRefresh}
              interval={localRefreshRateSeconds}
              onIntervalChange={handleRefreshRateChange}
              isRefreshing={isAutoRefreshing}
            />
          )}
        />

        <div ref={containerRef}>
          <ReactGridLayout
            className="layout"
            width={width}
            layout={widgetsWithLayout.map((w) => w.layout!)}
            gridConfig={{ margin: [20, 20], rowHeight: 50, cols: 12 }}
            dragConfig={{ enabled: false }}
            resizeConfig={{ enabled: false }}
          >
            {widgetsWithLayout.map((widget) => (
              <div
                key={widget.id}
              >
                <ErrorBoundary>
                  {widget.perspective === 'entities' && entityWidget(widget)}
                  {widget.perspective === 'relationships' && relationshipWidget(widget)}
                  {widget.perspective === 'audits' && auditWidget(widget)}
                  {widget.perspective === null && rawWidget(widget)}
                </ErrorBoundary>
              </div>
            ))}
          </ReactGridLayout>
        </div>
      </DashboardRefreshProvider>

    </>
  );
};

const PublicDashboard = () => {
  const { uriKey } = useParams();
  if (!uriKey) return null;

  const normalizedUriKey = uriKey.toLowerCase();

  const queryRef = useQueryLoading<PublicDashboardQuery>(
    publicDashboardQuery,
    { uri_key: normalizedUriKey },
  );

  return queryRef ? (
    <React.Suspense fallback={<Loader variant={LoaderVariant.container} />}>
      <PublicDashboardComponent
        queryRef={queryRef}
        uriKey={normalizedUriKey}
      />
    </React.Suspense>
  ) : (
    <Loader variant={LoaderVariant.container} />
  );
};

export default PublicDashboard;
