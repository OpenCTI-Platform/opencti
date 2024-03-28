import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import React from 'react';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import type { PublicWidgetContainerProps } from '../PublicWidgetContainerProps';
import { useFormatter } from '../../../../components/i18n';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetLoader from '../../../../components/dashboard/WidgetLoader';
import { PublicStixCoreObjectsTreeMapQuery } from './__generated__/PublicStixCoreObjectsTreeMapQuery.graphql';
import WidgetTree from '../../../../components/dashboard/WidgetTree';
import type { PublicManifestWidget } from '../PublicManifest';

const publicStixCoreObjectsTreeMapQuery = graphql`
  query PublicStixCoreObjectsTreeMapQuery(
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

interface PublicStixCoreObjectsTreeMapComponentProps {
  parameters: PublicManifestWidget['parameters']
  dataSelection: PublicManifestWidget['dataSelection']
  queryRef: PreloadedQuery<PublicStixCoreObjectsTreeMapQuery>
}

const PublicStixCoreObjectsTreeMapComponent = ({
  parameters,
  dataSelection,
  queryRef,
}: PublicStixCoreObjectsTreeMapComponentProps) => {
  const { publicStixCoreObjectsDistribution } = usePreloadedQuery(
    publicStixCoreObjectsTreeMapQuery,
    queryRef,
  );

  if (
    publicStixCoreObjectsDistribution
    && publicStixCoreObjectsDistribution.length > 0
  ) {
    return (
      <WidgetTree
        data={[...publicStixCoreObjectsDistribution]}
        groupBy={dataSelection[0].attribute ?? 'entity_type'}
        isDistributed={parameters.distributed}
        readonly={true}
        withExport={false}
      />
    );
  }
  return <WidgetNoData />;
};

const PublicStixCoreObjectsTreeMap = ({
  uriKey,
  widget,
  startDate,
  endDate,
  title,
}: PublicWidgetContainerProps) => {
  const { t_i18n } = useFormatter();
  const { id, parameters, dataSelection } = widget;
  const queryRef = useQueryLoading<PublicStixCoreObjectsTreeMapQuery>(
    publicStixCoreObjectsTreeMapQuery,
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
          <PublicStixCoreObjectsTreeMapComponent
            queryRef={queryRef}
            parameters={parameters}
            dataSelection={dataSelection}
          />
        </React.Suspense>
      ) : (
        <WidgetLoader />
      )}
    </WidgetContainer>
  );
};

export default PublicStixCoreObjectsTreeMap;
