import React, { useEffect, useMemo } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { useParams, useNavigate } from 'react-router-dom';
import RGL, { WidthProvider } from 'react-grid-layout';
import { ErrorBoundary } from '@components/Error';
import Paper from '@mui/material/Paper';
import Loader, { LoaderVariant } from '../../components/Loader';
import { PublicDashboardQuery } from './__generated__/PublicDashboardQuery.graphql';
import useQueryLoading from '../../utils/hooks/useQueryLoading';
import { fromB64 } from '../../utils/String';
import type { PublicManifest } from './dashboard/PublicManifest';
import usePublicDashboardWidgets from './dashboard/usePublicDashboardWidgets';
import PublicTopBar from './PublicTopBar';
import PublicDashboardHeader from './dashboard/PublicDashboardHeader';

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
  const ReactGridLayout = useMemo(() => WidthProvider(RGL), []);

  const { publicDashboardByUriKey } = usePreloadedQuery(publicDashboardQuery, queryRef);
  const manifest = publicDashboardByUriKey?.public_manifest;
  const parsedManifest: PublicManifest = JSON.parse(manifest ? fromB64(manifest) : '{}');
  const { widgets, config } = parsedManifest;

  useEffect(() => {
    if (publicDashboardByUriKey === null || !publicDashboardByUriKey?.enabled) {
      navigate('/');
    }
  }, [publicDashboardByUriKey, navigate]);

  const {
    entityWidget,
    relationshipWidget,
    rawWidget,
    auditWidget,
  } = usePublicDashboardWidgets(uriKey, config);

  const onChangeRelativeDate = () => {};
  const onChangeStartDate = () => {};
  const onChangeEndDate = () => {};

  if (!publicDashboardByUriKey || !config) {
    return null;
  }

  return (
    <>
      <PublicTopBar />
      <PublicDashboardHeader
        title={publicDashboardByUriKey?.name ?? ''}
        manifestConfig={config}
        onChangeRelativeDate={onChangeRelativeDate}
        onChangeStartDate={onChangeStartDate}
        onChangeEndDate={onChangeEndDate}
      />

      <ReactGridLayout
        className="layout"
        margin={[20, 20]}
        rowHeight={50}
        cols={12}
        isDraggable={false}
        isResizable={false}
      >
        {Object.values(widgets ?? {}).map((widget) => (
          <Paper
            key={widget.id}
            data-grid={widget.layout}
            variant="outlined"
            sx={{
              height: '100%',
              margin: 0,
              padding: '20px',
              borderRadius: '6px',
              display: 'relative',
              overflow: 'hidden',
            }}
          >
            <ErrorBoundary>
              {widget.perspective === 'entities' && entityWidget(widget)}
              {widget.perspective === 'relationships' && relationshipWidget(widget)}
              {widget.perspective === 'audits' && auditWidget(widget)}
              {widget.perspective === null && rawWidget(widget)}
            </ErrorBoundary>
          </Paper>
        ))}
      </ReactGridLayout>

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
