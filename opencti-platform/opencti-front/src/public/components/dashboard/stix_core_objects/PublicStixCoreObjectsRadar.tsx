import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import React from 'react';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import type { PublicWidgetContainerProps } from '../PublicWidgetContainerProps';
import { useFormatter } from '../../../../components/i18n';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetLoader from '../../../../components/dashboard/WidgetLoader';
import { PublicStixCoreObjectsRadarQuery } from './__generated__/PublicStixCoreObjectsRadarQuery.graphql';
import WidgetRadar from '../../../../components/dashboard/WidgetRadar';
import type { PublicManifestWidget } from '../PublicManifest';

const publicStixCoreObjectsRadarQuery = graphql`
  query PublicStixCoreObjectsRadarQuery(
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
        ... on StixRelationship {
          representative {
            main
          }
        }
        # internal objects
        ... on Creator {
          name
        }
        ... on Group {
          name
        }
        # need colors when available
        ... on Label {
          color
        }
        ... on MarkingDefinition {
          x_opencti_color
        }
        ... on Status {
          template {
            name
            color
          }
        }
      }
    }
  }
`;

interface PublicStixCoreObjectsRadarComponentProps {
  dataSelection: PublicManifestWidget['dataSelection']
  queryRef: PreloadedQuery<PublicStixCoreObjectsRadarQuery>
}

const PublicStixCoreObjectsRadarComponent = ({
  dataSelection,
  queryRef,
}: PublicStixCoreObjectsRadarComponentProps) => {
  const { publicStixCoreObjectsDistribution } = usePreloadedQuery(
    publicStixCoreObjectsRadarQuery,
    queryRef,
  );

  if (
    publicStixCoreObjectsDistribution
    && publicStixCoreObjectsDistribution.length > 0
  ) {
    return (
      <WidgetRadar
        data={[...publicStixCoreObjectsDistribution]}
        label={dataSelection[0].label ?? ''}
        groupBy={dataSelection[0].attribute ?? 'entity_type'}
        withExport={false}
        readonly={true}
      />
    );
  }
  return <WidgetNoData />;
};

const PublicStixCoreObjectsRadar = ({
  uriKey,
  widget,
  startDate,
  endDate,
  title,
}: PublicWidgetContainerProps) => {
  const { t_i18n } = useFormatter();
  const { id, parameters, dataSelection } = widget;
  const queryRef = useQueryLoading<PublicStixCoreObjectsRadarQuery>(
    publicStixCoreObjectsRadarQuery,
    {
      uriKey,
      widgetId: id,
      startDate,
      endDate,
    },
  );

  return (
    <WidgetContainer
      title={parameters.title ?? title ?? t_i18n('Entities number')}
      variant="inLine"
    >
      {queryRef ? (
        <React.Suspense fallback={<WidgetLoader />}>
          <PublicStixCoreObjectsRadarComponent
            queryRef={queryRef}
            dataSelection={dataSelection}
          />
        </React.Suspense>
      ) : (
        <WidgetLoader />
      )}
    </WidgetContainer>
  );
};

export default PublicStixCoreObjectsRadar;
