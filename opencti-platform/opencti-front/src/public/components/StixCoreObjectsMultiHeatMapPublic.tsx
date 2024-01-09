import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import Loader, { LoaderVariant } from '../../components/Loader';
import { StixCoreObjectsMultiHeatMapPublicQuery } from './__generated__/StixCoreObjectsMultiHeatMapPublicQuery.graphql';
import useQueryLoading from '../../utils/hooks/useQueryLoading';

const stixCoreObjectsMultiHeatMapPublicQuery = graphql`
  query StixCoreObjectsMultiHeatMapPublicQuery(
    $startDate: DateTime!
    $endDate: DateTime
    $interval: String!
    $onlyInferred: Boolean
    $uriKey: String!
    $widgetId : String!
  ) {
    publicStixCoreObjectsMultiTimeSeries(
      startDate: $startDate
      endDate: $endDate
      interval: $interval
      onlyInferred: $onlyInferred
      uriKey: $uriKey
      widgetId : $widgetId
    ) {
      data {
        date
        value
      }
    }
  }
`;

interface StixCoreObjectsMultiHeatMapPublicComponentProps {
  queryRef: PreloadedQuery<StixCoreObjectsMultiHeatMapPublicQuery>;
}

const StixCoreObjectsMultiHeatMapPublicComponent: FunctionComponent<StixCoreObjectsMultiHeatMapPublicComponentProps> = ({
  queryRef,
}) => {
  const data = usePreloadedQuery<StixCoreObjectsMultiHeatMapPublicQuery>(stixCoreObjectsMultiHeatMapPublicQuery, queryRef);
  const dataToDisplay = data?.publicStixCoreObjectsMultiTimeSeries;

  return (
    <div>
      {dataToDisplay[0].data.map((i) => <li>
        Date: {i.date} , Value: {i.value}
      </li>)}
    </div>
  );
};

interface StixCoreObjectsMultiHeatMapPublicProps {
  startDate: string;
  endDate: string;
  uriKey: string;
  widgetId: string;
}

const StixCoreObjectsMultiHeatMapPublic: FunctionComponent<StixCoreObjectsMultiHeatMapPublicProps> = ({
  uriKey,
  widgetId }) => {
  // uriKey: "a896c0a1-4917-4fea-bad3-8502c390303f"
  // widgetId: "687702dc-9237-4eb4-a16a-0c38044209e7

  const queryRef = useQueryLoading<StixCoreObjectsMultiHeatMapPublicQuery>(
    stixCoreObjectsMultiHeatMapPublicQuery,
    {
      startDate: '2023-01-08T00:00:00+01:00',
      endDate: '2024-01-08T14:09:42+01:00',
      interval: 'month',
      uriKey,
      widgetId,
    },
  );

  return (
    <>
      {queryRef ? (
        <React.Suspense fallback={<Loader variant={LoaderVariant.container} />}>
          <StixCoreObjectsMultiHeatMapPublicComponent
            queryRef={queryRef}
          />
        </React.Suspense>
      ) : (
        <Loader variant={LoaderVariant.container} />
      )}
    </>
  );
};

export default StixCoreObjectsMultiHeatMapPublic;
