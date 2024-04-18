import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import React from 'react';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import type { PublicWidgetContainerProps } from '../PublicWidgetContainerProps';
import { useFormatter } from '../../../../components/i18n';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetLoader from '../../../../components/dashboard/WidgetLoader';
import WidgetDistributionList from '../../../../components/dashboard/WidgetDistributionList';
import { PublicStixCoreObjectsDistributionListQuery } from './__generated__/PublicStixCoreObjectsDistributionListQuery.graphql';
import { getMainRepresentative } from '../../../../utils/defaultRepresentatives';

const publicStixCoreObjectsDistributionListQuery = graphql`
  query PublicStixCoreObjectsDistributionListQuery(
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

interface PublicStixCoreObjectsDistributionListComponentProps {
  queryRef: PreloadedQuery<PublicStixCoreObjectsDistributionListQuery>
}

const PublicStixCoreObjectsDistributionListComponent = ({
  queryRef,
}: PublicStixCoreObjectsDistributionListComponentProps) => {
  const { t_i18n } = useFormatter();
  const { publicStixCoreObjectsDistribution } = usePreloadedQuery(
    publicStixCoreObjectsDistributionListQuery,
    queryRef,
  );

  if (publicStixCoreObjectsDistribution && publicStixCoreObjectsDistribution.length > 0) {
    const data = publicStixCoreObjectsDistribution.flatMap((n) => {
      if (!n) return [];
      let { label } = n;
      if (t_i18n(`entity_${n.label}`) !== `entity_${n.label}`) {
        label = t_i18n(`entity_${n.label}`);
      }
      if (n.entity) {
        label = getMainRepresentative(n.entity);
      }
      return {
        label,
        value: n.value,
        color: n.entity?.color ?? n.entity?.x_opencti_color,
        id: n.entity?.id ?? null,
        type: n.entity?.entity_type ?? n.label,
      };
    });
    return <WidgetDistributionList data={data} publicWidget />;
  }
  return <WidgetNoData />;
};

const PublicStixCoreObjectsDistributionList = ({
  uriKey,
  widget,
  startDate,
  endDate,
  title,
}: PublicWidgetContainerProps) => {
  const { t_i18n } = useFormatter();
  const { id, parameters } = widget;
  const queryRef = useQueryLoading<PublicStixCoreObjectsDistributionListQuery>(
    publicStixCoreObjectsDistributionListQuery,
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
          <PublicStixCoreObjectsDistributionListComponent queryRef={queryRef} />
        </React.Suspense>
      ) : (
        <WidgetLoader />
      )}
    </WidgetContainer>
  );
};

export default PublicStixCoreObjectsDistributionList;
