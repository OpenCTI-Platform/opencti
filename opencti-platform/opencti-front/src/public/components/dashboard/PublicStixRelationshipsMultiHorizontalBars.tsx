import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import React from 'react';
import * as R from 'ramda';
import type { PublicManifestWidget } from './PublicManifest';
import { useFormatter } from '../../../components/i18n';
import { defaultValue } from '../../../utils/Graph';
import WidgetHorizontalBars from '../../../components/dashboard/WidgetHorizontalBars';
import WidgetNoData from '../../../components/dashboard/WidgetNoData';
import type { PublicWidgetContainerProps } from './publicWidgetContainerProps';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import WidgetContainer from '../../../components/dashboard/WidgetContainer';
import WidgetLoader from '../../../components/dashboard/WidgetLoader';
import { PublicStixRelationshipsMultiHorizontalBarsQuery } from './__generated__/PublicStixRelationshipsMultiHorizontalBarsQuery.graphql';

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
          entity_type
          id
        }
        ... on BasicRelationship {
          entity_type
          id
        }
        ... on AttackPattern {
          name
          description
        }
        ... on Campaign {
          name
          description
        }
        ... on CourseOfAction {
          name
          description
        }
        ... on Individual {
          name
          description
        }
        ... on Organization {
          name
          description
        }
        ... on Sector {
          name
          description
        }
        ... on System {
          name
          description
        }
        ... on Indicator {
          name
          description
        }
        ... on Infrastructure {
          name
          description
        }
        ... on IntrusionSet {
          name
          description
        }
        ... on Position {
          name
          description
        }
        ... on City {
          name
          description
        }
        ... on AdministrativeArea {
          name
          description
        }
        ... on Country {
          name
          description
        }
        ... on Region {
          name
          description
        }
        ... on Malware {
          name
          description
        }
        ... on ThreatActor {
          name
          description
        }
        ... on Tool {
          name
          description
        }
        ... on Vulnerability {
          name
          description
        }
        ... on Incident {
          name
          description
        }
        ... on Event {
          name
          description
        }
        ... on Channel {
          name
          description
        }
        ... on Narrative {
          name
          description
        }
        ... on Language {
          name
        }
        ... on DataComponent {
          name
        }
        ... on DataSource {
          name
        }
        ... on Case {
          name
        }
        ... on Report {
          name
        }
        ... on StixCyberObservable {
          observable_value
        }
        ... on MarkingDefinition {
          definition_type
          definition
          x_opencti_color
        }
        ... on KillChainPhase {
          kill_chain_name
          phase_name
        }
        ... on Creator {
          name
        }
        ... on Report {
          name
        }
        ... on Grouping {
          name
        }
        ... on Note {
          attribute_abstract
          content
        }
        ... on Opinion {
          opinion
        }
        ... on Label {
          value
          color
        }
      }
      breakdownDistribution {
        value
        label
        entity {
          ... on BasicObject {
            entity_type
            id
          }
          ... on BasicRelationship {
            entity_type
            id
          }
          ... on AttackPattern {
            name
            description
          }
          ... on Campaign {
            name
            description
          }
          ... on CourseOfAction {
            name
            description
          }
          ... on Individual {
            name
            description
          }
          ... on Organization {
            name
            description
          }
          ... on Sector {
            name
            description
          }
          ... on System {
            name
            description
          }
          ... on Indicator {
            name
            description
          }
          ... on Infrastructure {
            name
            description
          }
          ... on IntrusionSet {
            name
            description
          }
          ... on Position {
            name
            description
          }
          ... on City {
            name
            description
          }
          ... on Country {
            name
            description
          }
          ... on AdministrativeArea {
            name
            description
          }
          ... on Region {
            name
            description
          }
          ... on Malware {
            name
            description
          }
          ... on ThreatActor {
            name
            description
          }
          ... on Tool {
            name
            description
          }
          ... on Vulnerability {
            name
            description
          }
          ... on Incident {
            name
            description
          }
          ... on Event {
            name
            description
          }
          ... on Channel {
            name
            description
          }
          ... on Narrative {
            name
            description
          }
          ... on Language {
            name
          }
          ... on DataComponent {
            name
          }
          ... on DataSource {
            name
          }
          ... on Case {
            name
          }
          ... on Report {
            name
          }
          ... on StixCyberObservable {
            observable_value
          }
          ... on MarkingDefinition {
            definition_type
            definition
            x_opencti_color
          }
          ... on KillChainPhase {
            kill_chain_name
            phase_name
          }
          ... on Creator {
            name
          }
          ... on Report {
            name
          }
          ... on Grouping {
            name
          }
          ... on Note {
            attribute_abstract
            content
          }
          ... on Opinion {
            opinion
          }
          ... on Label {
            value
            color
          }
        }
      }
    }
  }
`;

interface PublicStixRelationshipsMultiHorizontalBarsComponentProps {
  parameters: PublicManifestWidget['parameters']
  dataSelection: PublicManifestWidget['dataSelection']
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

  if (
    publicStixRelationshipsDistribution
    && publicStixRelationshipsDistribution.length > 0
  ) {
    const selection = dataSelection[0];
    const finalField = selection.attribute || 'entity_type';
    const subSelection = dataSelection[1];
    const finalSubDistributionField = subSelection.attribute || 'entity_type';

    const categories = publicStixRelationshipsDistribution.map((n) => defaultValue(n?.entity));
    const entitiesMapping: Record<string, number> = {};
    for (const distrib of publicStixRelationshipsDistribution) {
      for (const subDistrib of distrib?.breakdownDistribution ?? []) {
        entitiesMapping[
          finalSubDistributionField === 'internal_id'
            ? defaultValue(subDistrib?.entity)
            : subDistrib?.label
        ] = (entitiesMapping[
          finalSubDistributionField === 'internal_id'
            ? defaultValue(subDistrib?.entity)
            : subDistrib?.label
        ] || 0) + (subDistrib?.value ?? 0);
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
              ? defaultValue(n?.entity)
              : n?.label) === sortedEntity[0],
          ),
        );
        let value = 0;
        if (entityData && entityData.value) {
          value = entityData.value;
        }
        if (categoriesValues[defaultValue(distrib?.entity)]) {
          categoriesValues[defaultValue(distrib?.entity)].push(value);
        } else {
          categoriesValues[defaultValue(distrib?.entity)] = [value];
        }
      }
      const sum = (
        categoriesValues[defaultValue(distrib?.entity)] || []
      ).reduce((partialSum, a) => partialSum + a, 0);
      if (categoriesValues[defaultValue(distrib?.entity)]) {
        categoriesValues[defaultValue(distrib?.entity)].push(
          (distrib?.value ?? 0) - sum,
        );
      } else {
        categoriesValues[defaultValue(distrib?.entity)] = [
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
        distributed={parameters.distributed}
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
      title={parameters.title ?? title ?? t_i18n('Distribution of entities')}
      variant="inLine"
    >
      {queryRef ? (
        <React.Suspense fallback={<WidgetLoader />}>
          <PublicStixRelationshipsMultiHorizontalBarsComponent
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

export default PublicStixRelationshipsMultiHorizontalBars;
