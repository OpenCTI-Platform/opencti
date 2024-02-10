import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import React from 'react';
import LocationMiniMapTargets from '@components/common/location/LocationMiniMapTargets';
import type { PublicManifestWidget } from './PublicManifest';
import WidgetNoData from '../../../components/dashboard/WidgetNoData';
import { computeLevel } from '../../../utils/Number';
import type { PublicWidgetContainerProps } from './publicWidgetContainerProps';
import { useFormatter } from '../../../components/i18n';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import WidgetContainer from '../../../components/dashboard/WidgetContainer';
import WidgetLoader from '../../../components/dashboard/WidgetLoader';
import { PublicStixRelationshipsMapQuery } from './__generated__/PublicStixRelationshipsMapQuery.graphql';

const publicStixRelationshipsMapQuery = graphql`
  query PublicStixRelationshipsMapQuery(
    $startDate: DateTime
    $endDate: DateTime
    $uriKey: String!
    $widgetId : String!
  ) {
    publicStixRelationshipsDistribution(
      startDate: $startDate
      endDate: $endDate
      uriKey: $uriKey
      widgetId : $widgetId
    ) {
      label
      value
      entity {
        ... on BasicObject {
          entity_type
        }
        ... on BasicRelationship {
          entity_type
        }
        ... on Country {
          name
          x_opencti_aliases
          latitude
          longitude
        }
        ... on City {
          name
          x_opencti_aliases
          latitude
          longitude
        }
      }
    }
  }
`;

interface PublicStixRelationshipsMapComponentProps {
  dataSelection: PublicManifestWidget['dataSelection']
  queryRef: PreloadedQuery<PublicStixRelationshipsMapQuery>
}

const PublicStixRelationshipsMapComponent = ({
  dataSelection,
  queryRef,
}: PublicStixRelationshipsMapComponentProps) => {
  const { publicStixRelationshipsDistribution } = usePreloadedQuery(
    publicStixRelationshipsMapQuery,
    queryRef,
  );

  if (
    publicStixRelationshipsDistribution
    && publicStixRelationshipsDistribution.length > 0
  ) {
    const values = publicStixRelationshipsDistribution.flatMap((node) => {
      if (node?.value === null || node?.value === undefined) return [];
      return node.value;
    });

    const countries = publicStixRelationshipsDistribution.flatMap((node) => {
      if (node?.entity?.entity_type !== 'Country') return [];
      return {
        ...node.entity,
        level: computeLevel(node.value, values[values.length - 1], values[0] + 1),
      };
    });

    const cities = publicStixRelationshipsDistribution.flatMap((node) => {
      if (node?.entity?.entity_type !== 'City') return [];
      return node.entity;
    });

    return (
      <LocationMiniMapTargets
        center={[dataSelection[0].centerLat ?? 48.8566969, dataSelection[0].centerLng ?? 2.3514616]}
        countries={countries}
        cities={cities}
        zoom={dataSelection[0].zoom ?? 2}
      />
    );
  }
  return <WidgetNoData />;
};

const PublicStixRelationshipsMap = ({
  uriKey,
  widget,
  startDate,
  endDate,
  title,
}: PublicWidgetContainerProps) => {
  const { t_i18n } = useFormatter();
  const { id, parameters, dataSelection } = widget;
  const queryRef = useQueryLoading<PublicStixRelationshipsMapQuery>(
    publicStixRelationshipsMapQuery,
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
          <PublicStixRelationshipsMapComponent
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

export default PublicStixRelationshipsMap;
