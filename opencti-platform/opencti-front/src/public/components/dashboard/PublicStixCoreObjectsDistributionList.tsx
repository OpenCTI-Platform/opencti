import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import React from 'react';
import WidgetNoData from '../../../components/dashboard/WidgetNoData';
import type { PublicWidgetContainerProps } from './publicWidgetContainerProps';
import { useFormatter } from '../../../components/i18n';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import WidgetContainer from '../../../components/dashboard/WidgetContainer';
import WidgetLoader from '../../../components/dashboard/WidgetLoader';
import WidgetDistributionList from '../../../components/dashboard/WidgetDistributionList';
import { PublicStixCoreObjectsDistributionListQuery } from './__generated__/PublicStixCoreObjectsDistributionListQuery.graphql';

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
        ... on StixObject {
          id
          entity_type
          representative {
            main
          }
        }
        ... on StixRelationship {
          id
          entity_type
          representative {
            main
          }
        }
        ... on Creator {
          id
          entity_type
          representative {
            main
          }
        }
        ... on Label {
          value
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
    const data = publicStixCoreObjectsDistribution.flatMap((o) => {
      if (!o) return [];
      return {
        label:
        // eslint-disable-next-line no-nested-ternary
          o.entity?.representative?.main
            ? o.entity?.representative?.main
            : t_i18n(`entity_${o.label}`) !== `entity_${o.label}`
              ? t_i18n(`entity_${o.label}`)
              : o.label,
        value: o.value,
        color: o.entity?.color ?? o.entity?.x_opencti_color,
        id: o.entity?.id ?? null,
        type: o.entity?.entity_type ?? o.label,
      };
    });
    return <WidgetDistributionList data={data} />;
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
