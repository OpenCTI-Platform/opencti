import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import React from 'react';
import { useFormatter } from '../../../../components/i18n';
import WidgetDistributionList from '../../../../components/dashboard/WidgetDistributionList';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import type { PublicWidgetContainerProps } from '../PublicWidgetContainerProps';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetLoader from '../../../../components/dashboard/WidgetLoader';
import { PublicStixRelationshipsDistributionListQuery } from './__generated__/PublicStixRelationshipsDistributionListQuery.graphql';
import type { PublicManifestWidget } from '../PublicManifest';
import { getMainRepresentative } from '../../../../utils/defaultRepresentatives';

const publicStixRelationshipsDistributionListQuery = graphql`
  query PublicStixRelationshipsDistributionListQuery(
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

interface PublicStixRelationshipsDistributionListComponentProps {
  dataSelection: PublicManifestWidget['dataSelection']
  queryRef: PreloadedQuery<PublicStixRelationshipsDistributionListQuery>
}

const PublicStixRelationshipsDistributionListComponent = ({
  dataSelection,
  queryRef,
}: PublicStixRelationshipsDistributionListComponentProps) => {
  const { publicStixRelationshipsDistribution } = usePreloadedQuery(
    publicStixRelationshipsDistributionListQuery,
    queryRef,
  );

  const { t_i18n } = useFormatter();

  if (publicStixRelationshipsDistribution && publicStixRelationshipsDistribution.length > 0) {
    const finalField = dataSelection[0].attribute || 'entity_type';
    const data = publicStixRelationshipsDistribution.flatMap((o) => {
      if (!o) return [];
      return {
        label: finalField.endsWith('_id')
          ? getMainRepresentative(o.entity, t_i18n('Restricted'))
          : o.label,
        value: o.value,
        id: o.entity?.id ?? null,
        type: o.entity?.entity_type ?? o.label,
      };
    });
    return <WidgetDistributionList data={data} publicWidget />;
  }
  return <WidgetNoData />;
};

const PublicStixRelationshipsDistributionList = ({
  uriKey,
  widget,
  startDate,
  endDate,
  title,
}: PublicWidgetContainerProps) => {
  const { t_i18n } = useFormatter();
  const { id, parameters, dataSelection } = widget;
  const queryRef = useQueryLoading<PublicStixRelationshipsDistributionListQuery>(
    publicStixRelationshipsDistributionListQuery,
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
          <PublicStixRelationshipsDistributionListComponent
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

export default PublicStixRelationshipsDistributionList;
