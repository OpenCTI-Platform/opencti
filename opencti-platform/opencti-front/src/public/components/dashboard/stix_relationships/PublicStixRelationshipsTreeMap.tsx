import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import React from 'react';
import WidgetTree from '../../../../components/dashboard/WidgetTree';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import type { PublicWidgetContainerProps } from '../PublicWidgetContainerProps';
import { useFormatter } from '../../../../components/i18n';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import { PublicStixRelationshipsTreeMapQuery } from './__generated__/PublicStixRelationshipsTreeMapQuery.graphql';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import type { Widget } from '../../../../utils/widget/widget';

const publicStixRelationshipsTreeMapsQuery = graphql`
  query PublicStixRelationshipsTreeMapQuery(
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
        # objects without representative
        ... on Creator {
          name
        }
        ... on Status {
          template {
            name
          }
        }
      }
    }
  }
`;

interface PublicStixRelationshipsTreeMapComponentProps {
  parameters: Widget['parameters']
  dataSelection: Widget['dataSelection']
  queryRef: PreloadedQuery<PublicStixRelationshipsTreeMapQuery>
}

const PublicStixRelationshipsTreeMapComponent = ({
  parameters,
  dataSelection,
  queryRef,
}: PublicStixRelationshipsTreeMapComponentProps) => {
  const { publicStixRelationshipsDistribution } = usePreloadedQuery(
    publicStixRelationshipsTreeMapsQuery,
    queryRef,
  );

  if (
    publicStixRelationshipsDistribution
    && publicStixRelationshipsDistribution.length > 0
  ) {
    return (
      <WidgetTree
        data={[...publicStixRelationshipsDistribution]}
        groupBy={dataSelection[0].attribute ?? 'entity_type'}
        isDistributed={!!parameters?.distributed}
        readonly={true}
        withExport={false}
      />
    );
  }
  return <WidgetNoData />;
};

const PublicStixRelationshipsTreeMap = ({
  uriKey,
  widget,
  startDate,
  endDate,
  title,
}: PublicWidgetContainerProps) => {
  const { t_i18n } = useFormatter();
  const { id, parameters, dataSelection } = widget;
  const queryRef = useQueryLoading<PublicStixRelationshipsTreeMapQuery>(
    publicStixRelationshipsTreeMapsQuery,
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
          <PublicStixRelationshipsTreeMapComponent
            queryRef={queryRef}
            parameters={parameters}
            dataSelection={dataSelection}
          />
        </React.Suspense>
      ) : (
        <Loader variant={LoaderVariant.inElement} />
      )}
    </WidgetContainer>
  );
};

export default PublicStixRelationshipsTreeMap;
