import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import React from 'react';
import WidgetDonut from '../../../../components/dashboard/WidgetDonut';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import type { PublicWidgetContainerProps } from '../PublicWidgetContainerProps';
import { useFormatter } from '../../../../components/i18n';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import { PublicStixRelationshipsDonutQuery } from './__generated__/PublicStixRelationshipsDonutQuery.graphql';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import type { Widget } from '../../../../utils/widget/widget';

const publicStixRelationshipsDonutQuery = graphql`
  query PublicStixRelationshipsDonutQuery(
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

interface PublicStixRelationshipsDonutComponentProps {
  dataSelection: Widget['dataSelection']
  queryRef: PreloadedQuery<PublicStixRelationshipsDonutQuery>
}

const PublicStixRelationshipsDonutComponent = ({
  dataSelection,
  queryRef,
}: PublicStixRelationshipsDonutComponentProps) => {
  const { publicStixRelationshipsDistribution } = usePreloadedQuery(
    publicStixRelationshipsDonutQuery,
    queryRef,
  );

  if (
    publicStixRelationshipsDistribution
    && publicStixRelationshipsDistribution.length > 0
  ) {
    return (
      <WidgetDonut
        data={[...publicStixRelationshipsDistribution]}
        groupBy={dataSelection[0].attribute ?? 'entity_type'}
        withExport={false}
        readonly={true}
      />
    );
  }
  return <WidgetNoData />;
};

const PublicStixRelationshipsDonut = ({
  uriKey,
  widget,
  startDate,
  endDate,
  title,
}: PublicWidgetContainerProps) => {
  const { t_i18n } = useFormatter();
  const { id, parameters, dataSelection } = widget;
  const queryRef = useQueryLoading<PublicStixRelationshipsDonutQuery>(
    publicStixRelationshipsDonutQuery,
    {
      uriKey,
      widgetId: id,
      startDate,
      endDate,
    },
  );

  return (
    <WidgetContainer
      title={parameters?.title ?? title ?? t_i18n('Entities number')}
      variant="inLine"
    >
      {queryRef ? (
        <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
          <PublicStixRelationshipsDonutComponent
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

export default PublicStixRelationshipsDonut;
