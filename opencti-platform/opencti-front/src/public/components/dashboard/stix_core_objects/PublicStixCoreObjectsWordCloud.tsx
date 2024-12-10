import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import React from 'react';
import { useFormatter } from '../../../../components/i18n';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import type { PublicWidgetContainerProps } from '../PublicWidgetContainerProps';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { PublicStixCoreObjectsDistributionListQuery } from './__generated__/PublicStixCoreObjectsDistributionListQuery.graphql';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import WidgetWordCloud from '../../../../components/dashboard/WidgetWordCloud';
import type { Widget } from '../../../../utils/widget/widget';
import { PublicStixCoreObjectsWordCloudQuery } from './__generated__/PublicStixCoreObjectsWordCloudQuery.graphql';

const publicStixCoreObjectsWordCloudQuery = graphql`
  query PublicStixCoreObjectsWordCloudQuery(
    $startDate: DateTime
    $endDate: DateTime
    $uriKey: String!
    $widgetId : String!
  ) {
    publicStixCoreObjectsDistribution(
      startDate: $startDate
      endDate: $endDate
      uriKey: $uriKey
      widgetId : $widgetId
    ) {
      label
      value
      entity {
        ... on BasicObject {
          id
          entity_type
        }
        ... on BasicRelationship {
          id
          entity_type
        }
        ... on StixObject {
          representative {
            main
          }
        }

        # need colors when available
        ... on Label {
          color
        }
        ... on MarkingDefinition {
          x_opencti_color
        }

        # internal objects
        ... on Creator {
          name
        }
        ... on Group {
          name
        }
      }
    }
  }
`;

interface PublicStixCoreObjectsWordCloudComponentProps {
  queryRef: PreloadedQuery<PublicStixCoreObjectsWordCloudQuery>
  dataSelection: Widget['dataSelection']
}

const PublicStixCoreObjectsWordCloudComponent = ({
  queryRef,
  dataSelection,
}: PublicStixCoreObjectsWordCloudComponentProps) => {
  const { publicStixCoreObjectsDistribution } = usePreloadedQuery(
    publicStixCoreObjectsWordCloudQuery,
    queryRef,
  );

  if (
    publicStixCoreObjectsDistribution
    && publicStixCoreObjectsDistribution.length > 0
  ) {
    return <WidgetWordCloud data={[...publicStixCoreObjectsDistribution]} groupBy={dataSelection[0].attribute ?? 'entity_type'}/>;
  }
  return <WidgetNoData />;
};

const PublicStixCoreObjectsWordCloud = ({
  uriKey,
  widget,
  startDate,
  endDate,
  title,
}: PublicWidgetContainerProps) => {
  const { t_i18n } = useFormatter();
  const { id, parameters, dataSelection } = widget;
  const queryRef = useQueryLoading<PublicStixCoreObjectsDistributionListQuery>(
    publicStixCoreObjectsWordCloudQuery,
    {
      uriKey,
      widgetId: id,
      startDate,
      endDate,
    },
  );

  return (
    <WidgetContainer
      title={parameters?.title ?? title ?? t_i18n('Distribution of entities')}
      variant="inLine"
    >
      {queryRef ? (
        <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
          <PublicStixCoreObjectsWordCloudComponent
            queryRef={queryRef}
            dataSelection={dataSelection}
          />
        </React.Suspense>
      ) : (
        <Loader variant={LoaderVariant.inElement} />
      )}
    </WidgetContainer>
  );
};
export default PublicStixCoreObjectsWordCloud;
