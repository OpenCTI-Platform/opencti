import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import React from 'react';
import type { PublicManifestWidget } from '../PublicManifest';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import type { PublicWidgetContainerProps } from '../PublicWidgetContainerProps';
import { useFormatter } from '../../../../components/i18n';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetLoader from '../../../../components/dashboard/WidgetLoader';
import { PublicStixRelationshipsPolarAreaQuery } from './__generated__/PublicStixRelationshipsPolarAreaQuery.graphql';
import WidgetPolarArea from '../../../../components/dashboard/WidgetPolarArea';
import { getMainRepresentative, isFieldForIdentifier } from '../../../../utils/defaultRepresentatives';

const publicStixRelationshipsPolarAreaQuery = graphql`
  query PublicStixRelationshipsPolarAreaQuery(
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

interface PublicStixRelationshipsPolarAreaComponentProps {
  dataSelection: PublicManifestWidget['dataSelection']
  queryRef: PreloadedQuery<PublicStixRelationshipsPolarAreaQuery>
}

const PublicStixRelationshipsPolarAreaComponent = ({
  dataSelection,
  queryRef,
}: PublicStixRelationshipsPolarAreaComponentProps) => {
  const { publicStixRelationshipsDistribution } = usePreloadedQuery(
    publicStixRelationshipsPolarAreaQuery,
    queryRef,
  );

  if (
    publicStixRelationshipsDistribution
    && publicStixRelationshipsDistribution.length > 0
  ) {
    const attributeField = dataSelection[0].attribute || 'entity_type';

    // TODO: take into account the entity color to send it to the widget (that shall handle it)
    return (
      <WidgetPolarArea
        data={publicStixRelationshipsDistribution.flatMap((item) => {
          if (!item) {
            return [];
          }
          return {
            label: isFieldForIdentifier(attributeField)
              ? getMainRepresentative(item.entity)
              : item.label,
            value: item.value ?? 0,
          };
        })}
        withExport={false}
        readonly={true}
      />
    );
  }
  return <WidgetNoData />;
};

const PublicStixRelationshipsPolarArea = ({
  uriKey,
  widget,
  startDate,
  endDate,
  title,
}: PublicWidgetContainerProps) => {
  const { t_i18n } = useFormatter();
  const { id, parameters, dataSelection } = widget;
  const queryRef = useQueryLoading<PublicStixRelationshipsPolarAreaQuery>(
    publicStixRelationshipsPolarAreaQuery,
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
          <PublicStixRelationshipsPolarAreaComponent
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

export default PublicStixRelationshipsPolarArea;
