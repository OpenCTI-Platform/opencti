import React, { FunctionComponent, useMemo } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { useParams } from 'react-router-dom';
import RGL, { WidthProvider } from 'react-grid-layout';
import { ErrorBoundary, SimpleError } from '@components/Error';
import Paper from '@mui/material/Paper';
import Loader, { LoaderVariant } from '../../components/Loader';
import { daysAgo, dayStartDate, monthsAgo, yearsAgo } from '../../utils/Time';
import { PublicDashboardQuery } from './__generated__/PublicDashboardQuery.graphql';
import useQueryLoading from '../../utils/hooks/useQueryLoading';
import { fromB64 } from '../../utils/String';
import StixCoreObjectsMultiHeatMapPublic from './StixCoreObjectsMultiHeatMapPublic';

const publicDashboardQuery = graphql`
  query PublicDashboardQuery(
    $uri_key: String!
  ) {
    publicDashboardPublic(
      uri_key: $uri_key
    ) {
      name
      public_manifest  
    }
  }
`;

interface PublicDashboardComponentProps {
  queryRef: PreloadedQuery<PublicDashboardQuery>;
  uriKey: string;
}

const PublicDashboardComponent: FunctionComponent<PublicDashboardComponentProps> = ({ queryRef, uriKey }) => {
  const ReactGridLayout = useMemo(() => WidthProvider(RGL), []);

  const publicDashboard = usePreloadedQuery<PublicDashboardQuery>(publicDashboardQuery, queryRef);
  const manifest = publicDashboard.publicDashboardPublic?.public_manifest;
  const parsedManifest = JSON.parse(fromB64(manifest ?? '{}'));
  const { config, widgets } = parsedManifest;

  const widget = widgets['687702dc-9237-4eb4-a16a-0c38044209e7']; // HARDCODED FOR NOW TO GET HEAT MAP
  const { relativeDate } = config;

  const getDayStartDate = () => {
    return dayStartDate(null, false);
  };

  const computerRelativeDate = () => {
    if (relativeDate) {
      if (relativeDate.includes('days')) {
        return daysAgo(relativeDate.split('-')[1], null, false);
      }
      if (relativeDate.includes('months')) {
        return monthsAgo(relativeDate.split('-')[1]);
      }
      if (relativeDate.includes('years')) {
        return yearsAgo(relativeDate.split('-')[1]);
      }
    }
    return null;
  };

  const startDate = relativeDate
    ? computerRelativeDate()
    : config.startDate;
  const endDate = relativeDate ? getDayStartDate() : config.endDate;

  return (
    <>
      <ReactGridLayout
        className="layout"
        margin={[20, 20]}
        rowHeight={50}
        cols={12}
        isDraggable={false}
        isResizable={false}
      >
        {[widget].map((w) => (
          <Paper
            key={w.id}
            data-grid={w.layout}
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
              <StixCoreObjectsMultiHeatMapPublic
                startDate={startDate}
                endDate={endDate}
                uriKey={uriKey}
                widgetId={w.id}
              />
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
