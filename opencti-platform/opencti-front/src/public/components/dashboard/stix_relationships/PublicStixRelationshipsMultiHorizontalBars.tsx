import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import React from 'react';
import * as R from 'ramda';
import { useFormatter } from '../../../../components/i18n';
import { getMainRepresentative } from '../../../../utils/defaultRepresentatives';
import WidgetHorizontalBars from '../../../../components/dashboard/WidgetHorizontalBars';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import type { PublicWidgetContainerProps } from '../PublicWidgetContainerProps';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import { PublicStixRelationshipsMultiHorizontalBarsQuery } from './__generated__/PublicStixRelationshipsMultiHorizontalBarsQuery.graphql';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import type { Widget } from '../../../../utils/widget/widget';

const publicStixRelationshipsMultiHorizontalBarsQuery = graphql`
  query PublicStixRelationshipsMultiHorizontalBarsQuery(
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
      breakdownDistribution {
        value
        label
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
            id
            name
          }
          ... on Group {
            id
            name
          }
          # need colors when available
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
  }
`;

interface PublicStixRelationshipsMultiHorizontalBarsComponentProps {
  parameters: Widget['parameters']
  dataSelection: Widget['dataSelection']
  queryRef: PreloadedQuery<PublicStixRelationshipsMultiHorizontalBarsQuery>
}

const PublicStixRelationshipsMultiHorizontalBarsComponent = ({
  parameters,
  dataSelection,
  queryRef,
}: PublicStixRelationshipsMultiHorizontalBarsComponentProps) => {
  const { publicStixRelationshipsDistribution } = usePreloadedQuery(
    publicStixRelationshipsMultiHorizontalBarsQuery,
    queryRef,
  );

  const { t_i18n } = useFormatter();

  if (
    publicStixRelationshipsDistribution
    && publicStixRelationshipsDistribution.length > 0
  ) {
    const selection = dataSelection[0];
    const finalField = selection.attribute || 'entity_type';
    const subSelection = dataSelection[1];
    const finalSubDistributionField = subSelection.attribute || 'entity_type';

    const categories = publicStixRelationshipsDistribution.map((n) => getMainRepresentative(n?.entity));
    const entitiesMapping: Record<string, number> = {};
    for (const distrib of publicStixRelationshipsDistribution) {
      for (const subDistrib of distrib?.breakdownDistribution ?? []) {
        if (distrib && subDistrib) {
          entitiesMapping[
            finalSubDistributionField === 'internal_id'
              ? getMainRepresentative(subDistrib?.entity)
              : subDistrib?.label
          ] = (entitiesMapping[
            finalSubDistributionField === 'internal_id'
              ? getMainRepresentative(subDistrib?.entity)
              : subDistrib?.label
          ] || 0) + (subDistrib?.value ?? 0);
        }
      }
    }
    const sortedEntityMapping = R.take(
      subSelection.number ?? 15,
      Object.entries(entitiesMapping).sort(([, a], [, b]) => b - a),
    );
    const categoriesValues: Record<string, number[]> = {};
    for (const distrib of publicStixRelationshipsDistribution) {
      for (const sortedEntity of sortedEntityMapping) {
        const entityData = R.head(
          (distrib?.breakdownDistribution ?? []).filter(
            (n) => (finalSubDistributionField === 'internal_id'
              ? getMainRepresentative(n?.entity, t_i18n('Restricted'))
              : n?.label) === sortedEntity[0],
          ),
        );
        let value = 0;
        if (entityData && entityData.value) {
          value = entityData.value;
        }
        if (categoriesValues[getMainRepresentative(distrib?.entity)]) {
          categoriesValues[getMainRepresentative(distrib?.entity)].push(value);
        } else {
          categoriesValues[getMainRepresentative(distrib?.entity)] = [value];
        }
      }
      const sum = (
        categoriesValues[getMainRepresentative(distrib?.entity)] || []
      ).reduce((partialSum, a) => partialSum + a, 0);
      if (categoriesValues[getMainRepresentative(distrib?.entity)]) {
        categoriesValues[getMainRepresentative(distrib?.entity)].push(
          (distrib?.value ?? 0) - sum,
        );
      } else {
        categoriesValues[getMainRepresentative(distrib?.entity)] = [
          (distrib?.value ?? 0) - sum,
        ];
      }
    }
    sortedEntityMapping.push(['Others', 0]);
    const chartData = sortedEntityMapping.map((n, k) => {
      return {
        name: n[0],
        data: Object.entries(categoriesValues).map((o) => o[1][k]),
      };
    });
    const subSectionIds: Record<string, number> = {};
    if (
      finalField === 'internal_id'
      && finalSubDistributionField === 'internal_id'
    ) {
      // find subbars orders for entity subbars redirection
      for (const distrib of publicStixRelationshipsDistribution) {
        for (const subDistrib of (distrib?.breakdownDistribution ?? [])) {
          if (subDistrib?.label) {
            subSectionIds[subDistrib.label] = (subSectionIds[subDistrib.label] || 0)
              + (subDistrib.value ?? 0);
          }
        }
      }
    }
    const subSectionIdsOrder = R.take(
      subSelection.number ?? 15,
      Object.entries(subSectionIds)
        .sort(([, a], [, b]) => b - a)
        .map((k) => k[0]),
    );
    const redirectionUtils = finalField === 'internal_id'
      ? publicStixRelationshipsDistribution.map((n) => ({
        id: n?.label,
        entity_type: n?.entity?.entity_type,
        series: subSectionIdsOrder.map((subSectionId) => {
          const [entity] = (n?.breakdownDistribution ?? []).filter(
            (e) => e?.label === subSectionId,
          );
          return {
            id: subSectionId,
            entity_type: entity ? entity.entity?.entity_type : null,
          };
        }),
      }))
      : undefined;

    return (
      <WidgetHorizontalBars
        series={chartData}
        distributed={!!parameters?.distributed}
        withExport={false}
        readonly={true}
        redirectionUtils={redirectionUtils}
        stacked
        total
        legend
        categories={categories}
      />
    );
  }
  return <WidgetNoData />;
};

const PublicStixRelationshipsMultiHorizontalBars = ({
  uriKey,
  widget,
  startDate,
  endDate,
  title,
}: PublicWidgetContainerProps) => {
  const { t_i18n } = useFormatter();
  const { id, parameters, dataSelection } = widget;
  const queryRef = useQueryLoading<PublicStixRelationshipsMultiHorizontalBarsQuery>(
    publicStixRelationshipsMultiHorizontalBarsQuery,
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
          <PublicStixRelationshipsMultiHorizontalBarsComponent
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

export default PublicStixRelationshipsMultiHorizontalBars;
