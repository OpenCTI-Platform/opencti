import React, { useEffect, useMemo } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { useParams } from 'react-router-dom';
import RGL, { WidthProvider } from 'react-grid-layout';
import { ErrorBoundary, SimpleError } from '@components/Error';
import Paper from '@mui/material/Paper';
import { redirect, useNavigate } from 'react-router-dom-v5-compat';
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
    if (publicDashboardByUriKey === null) {
      navigate('/');
    }
  }, [publicDashboardByUriKey]);

  const {
    entityWidget,
    relationshipWidget,
    rawWidget,
  } = usePublicDashboardWidgets(uriKey, config);

  const onChangeRelativeDate = (value: string) => {
    console.log('relative date', value);
  };

  const onChangeStartDate = (value: string | null) => {
    console.log('start date', value);
  };

  const onChangeEndDate = (value: string | null) => {
    console.log('end date', value);
  };

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
            <ErrorBoundary
              display={
                <div style={{ paddingTop: 28 }}>
                  <SimpleError />
                </div>
              }
            >
              {widget.perspective === 'entities' && entityWidget(widget)}
              {widget.perspective === 'relationships' && relationshipWidget(widget)}
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

  const queryRef = useQueryLoading<PublicDashboardQuery>(
    publicDashboardQuery,
    { uri_key: uriKey },
  );

  return queryRef ? (
    <React.Suspense fallback={<Loader variant={LoaderVariant.container} />}>
      <PublicDashboardComponent
        queryRef={queryRef}
        uriKey={uriKey}
      />
    </React.Suspense>
  ) : (
    <Loader variant={LoaderVariant.container} />
  );
};

export default PublicDashboard;
