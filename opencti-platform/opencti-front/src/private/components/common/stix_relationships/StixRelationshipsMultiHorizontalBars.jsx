import React from 'react';
import { graphql } from 'react-relay';
import * as R from 'ramda';
import { QueryRenderer } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import { defaultValue } from '../../../../utils/Graph';
import { buildFiltersAndOptionsForWidgets } from '../../../../utils/filters/filtersUtils';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import WidgetLoader from '../../../../components/dashboard/WidgetLoader';
import WidgetHorizontalBars from '../../../../components/dashboard/WidgetHorizontalBars';

const stixRelationshipsMultiHorizontalBarsWithRelationshipsDistributionQuery = graphql`
  query StixRelationshipsMultiHorizontalBarsWithRelationshipsDistributionQuery(
    $field: String!
    $operation: StatsOperation!
    $startDate: DateTime
    $endDate: DateTime
    $dateAttribute: String
    $isTo: Boolean
    $limit: Int
    $fromOrToId: [String]
    $elementWithTargetTypes: [String]
    $fromId: [String]
    $fromRole: String
    $fromTypes: [String]
    $toId: [String]
    $toRole: String
    $toTypes: [String]
    $relationship_type: [String]
    $confidences: [Int]
    $search: String
    $filters: FilterGroup
    $dynamicFrom: FilterGroup
    $dynamicTo: FilterGroup
    $subDistributionField: String!
    $subDistributionOperation: StatsOperation!
    $subDistributionStartDate: DateTime
    $subDistributionEndDate: DateTime
    $subDistributionDateAttribute: String
    $subDistributionIsTo: Boolean
    $subDistributionLimit: Int
    $subDistributionElementWithTargetTypes: [String]
    $subDistributionFromId: [String]
    $subDistributionFromRole: String
    $subDistributionFromTypes: [String]
    $subDistributionToId: [String]
    $subDistributionToRole: String
    $subDistributionToTypes: [String]
    $subDistributionRelationshipType: [String]
    $subDistributionConfidences: [Int]
    $subDistributionSearch: String
    $subDistributionFilters: FilterGroup
  ) {
    stixRelationshipsDistribution(
      field: $field
      operation: $operation
      startDate: $startDate
      endDate: $endDate
      dateAttribute: $dateAttribute
      isTo: $isTo
      limit: $limit
      fromOrToId: $fromOrToId
      elementWithTargetTypes: $elementWithTargetTypes
      fromId: $fromId
      fromRole: $fromRole
      fromTypes: $fromTypes
      toId: $toId
      toRole: $toRole
      toTypes: $toTypes
      relationship_type: $relationship_type
      confidences: $confidences
      search: $search
      filters: $filters
      dynamicFrom: $dynamicFrom
      dynamicTo: $dynamicTo
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
        ... on StixCoreObject {
          stixCoreRelationshipsDistribution(
            field: $subDistributionField
            operation: $subDistributionOperation
            startDate: $subDistributionStartDate
            endDate: $subDistributionEndDate
            dateAttribute: $subDistributionDateAttribute
            isTo: $subDistributionIsTo
            limit: $subDistributionLimit
            elementWithTargetTypes: $subDistributionElementWithTargetTypes
            fromId: $subDistributionFromId
            fromRole: $subDistributionFromRole
            fromTypes: $subDistributionFromTypes
            toId: $subDistributionToId
            toRole: $subDistributionToRole
            toTypes: $subDistributionToTypes
            relationship_type: $subDistributionRelationshipType
            confidences: $subDistributionConfidences
            search: $subDistributionSearch
            filters: $subDistributionFilters
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
                description
              }
              ... on DataSource {
                name
                description
              }
              ... on Case {
                name
                description
              }
              ... on StixCyberObservable {
                observable_value
              }
              ... on MarkingDefinition {
                definition_type
                definition
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
            }
          }
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
        ... on StixCyberObservable {
          observable_value
        }
        ... on MarkingDefinition {
          definition_type
          definition
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
      }
    }
  }
`;

const stixRelationshipsMultiHorizontalBarsWithEntitiesDistributionQuery = graphql`
  query StixRelationshipsMultiHorizontalBarsWithEntitiesDistributionQuery(
    $field: String!
    $operation: StatsOperation!
    $startDate: DateTime
    $endDate: DateTime
    $dateAttribute: String
    $isTo: Boolean
    $limit: Int
    $fromOrToId: [String]
    $elementWithTargetTypes: [String]
    $fromId: [String]
    $fromRole: String
    $fromTypes: [String]
    $toId: [String]
    $toRole: String
    $toTypes: [String]
    $relationship_type: [String]
    $confidences: [Int]
    $search: String
    $filters: FilterGroup
    $dynamicFrom: FilterGroup
    $dynamicTo: FilterGroup
    $subDistributionRelationshipType: [String]
    $subDistributionToTypes: [String]
    $subDistributionField: String!
    $subDistributionStartDate: DateTime
    $subDistributionEndDate: DateTime
    $subDistributionDateAttribute: String
    $subDistributionOperation: StatsOperation!
    $subDistributionLimit: Int
    $subDistributionOrder: String
    $subDistributionTypes: [String]
    $subDistributionFilters: FilterGroup
    $subDistributionSearch: String
  ) {
    stixRelationshipsDistribution(
      field: $field
      operation: $operation
      startDate: $startDate
      endDate: $endDate
      dateAttribute: $dateAttribute
      isTo: $isTo
      limit: $limit
      fromOrToId: $fromOrToId
      elementWithTargetTypes: $elementWithTargetTypes
      fromId: $fromId
      fromRole: $fromRole
      fromTypes: $fromTypes
      toId: $toId
      toRole: $toRole
      toTypes: $toTypes
      relationship_type: $relationship_type
      confidences: $confidences
      search: $search
      filters: $filters
      dynamicFrom: $dynamicFrom
      dynamicTo: $dynamicTo
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
        ... on StixCoreObject {
          stixCoreObjectsDistribution(
            relationship_type: $subDistributionRelationshipType
            toTypes: $subDistributionToTypes
            field: $subDistributionField
            startDate: $subDistributionStartDate
            endDate: $subDistributionEndDate
            dateAttribute: $subDistributionDateAttribute
            operation: $subDistributionOperation
            limit: $subDistributionLimit
            order: $subDistributionOrder
            types: $subDistributionTypes
            filters: $subDistributionFilters
            search: $subDistributionSearch
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
                description
              }
              ... on DataSource {
                name
                description
              }
              ... on Case {
                name
                description
              }
              ... on StixCyberObservable {
                observable_value
              }
              ... on MarkingDefinition {
                definition_type
                definition
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
            }
          }
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
        ... on StixCyberObservable {
          observable_value
        }
        ... on MarkingDefinition {
          definition_type
          definition
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
      }
    }
  }
`;

const StixRelationshipsMultiHorizontalBars = ({
  title,
  variant,
  height,
  field,
  startDate,
  endDate,
  dateAttribute,
  dataSelection,
  parameters = {},
  withExportPopover = false,
  isReadOnly = false,
}) => {
  const { t_i18n } = useFormatter();
  const renderContent = () => {
    let selection = {};
    let dataSelectionDateAttribute = null;
    let filtersAndOptions;
    let subDistributionFiltersAndOptions;
    let subSelection = {};
    let subDistributionTypes = null;
    if (dataSelection) {
      // eslint-disable-next-line prefer-destructuring
      selection = dataSelection[0];
      dataSelectionDateAttribute = selection.date_attribute && selection.date_attribute.length > 0
        ? selection.date_attribute
        : 'created_at';
      filtersAndOptions = buildFiltersAndOptionsForWidgets(selection.filters);
      if (dataSelection.length > 1) {
        // eslint-disable-next-line prefer-destructuring
        subSelection = dataSelection[1];
        subDistributionFiltersAndOptions = buildFiltersAndOptionsForWidgets(subSelection.filters);
        if (subSelection.perspective === 'entities') {
          subDistributionTypes = ['Stix-Core-Object'];
        }
      }
    }
    const finalField = selection.attribute || field || 'entity_type';
    let variables = {
      field: finalField,
      operation: 'count',
      startDate,
      endDate,
      dateAttribute: dateAttribute || dataSelectionDateAttribute,
      limit: selection.number ?? 10,
      filters: filtersAndOptions?.filters,
      isTo: selection.isTo,
      dynamicFrom: selection.dynamicFrom,
      dynamicTo: selection.dynamicTo,
    };
    const finalSubDistributionField = subSelection.attribute || field || 'entity_type';
    if (subSelection.perspective === 'entities') {
      variables = {
        ...variables,
        subDistributionField: finalSubDistributionField,
        subDistributionStartDate: startDate,
        subDistributionEndDate: endDate,
        subDistributionDateAttribute:
          subSelection.date_attribute && subSelection.date_attribute.length > 0
            ? subSelection.date_attribute
            : 'created_at',
        subDistributionOperation: 'count',
        subDistributionLimit: subSelection.number ?? 15,
        subDistributionTypes,
        subDistributionFilters: subDistributionFiltersAndOptions?.filters,
      };
    } else {
      variables = {
        ...variables,
        subDistributionField: finalSubDistributionField,
        subDistributionOperation: 'count',
        subDistributionStartDate: startDate,
        subDistributionEndDate: endDate,
        subDistributionDateAttribute:
          subSelection.date_attribute && subSelection.date_attribute.length > 0
            ? subSelection.date_attribute
            : 'created_at',
        subDistributionIsTo: subSelection.isTo,
        subDistributionLimit: subSelection.number ?? 15,
        subDistributionFilters: subDistributionFiltersAndOptions?.filters,
      };
    }
    return (
      <QueryRenderer
        query={
          subSelection.perspective === 'entities'
            ? stixRelationshipsMultiHorizontalBarsWithEntitiesDistributionQuery
            : stixRelationshipsMultiHorizontalBarsWithRelationshipsDistributionQuery
        }
        variables={variables}
        render={({ props }) => {
          const key = subSelection.perspective === 'entities'
            ? 'stixCoreObjectsDistribution'
            : 'stixCoreRelationshipsDistribution';
          if (
            props
            && props.stixRelationshipsDistribution
            && props.stixRelationshipsDistribution.length > 0
          ) {
            const categories = props.stixRelationshipsDistribution.map((n) => defaultValue(n.entity));
            const entitiesMapping = {};
            for (const distrib of props.stixRelationshipsDistribution) {
              for (const subDistrib of distrib.entity[key]) {
                entitiesMapping[
                  finalSubDistributionField === 'internal_id'
                    ? defaultValue(subDistrib.entity)
                    : subDistrib.label
                ] = (entitiesMapping[
                  finalSubDistributionField === 'internal_id'
                    ? defaultValue(subDistrib.entity)
                    : subDistrib.label
                ] || 0) + subDistrib.value;
              }
            }
            const sortedEntityMapping = R.take(
              subSelection.number ?? 15,
              Object.entries(entitiesMapping).sort(([, a], [, b]) => b - a),
            );
            const categoriesValues = {};
            for (const distrib of props.stixRelationshipsDistribution) {
              for (const sortedEntity of sortedEntityMapping) {
                const entityData = R.head(
                  distrib.entity[key].filter(
                    (n) => (finalSubDistributionField === 'internal_id'
                      ? defaultValue(n.entity)
                      : n.label) === sortedEntity[0],
                  ),
                );
                let value = 0;
                if (entityData) {
                  value = entityData.value;
                }
                if (categoriesValues[defaultValue(distrib.entity)]) {
                  categoriesValues[defaultValue(distrib.entity)].push(value);
                } else {
                  categoriesValues[defaultValue(distrib.entity)] = [value];
                }
              }
              const sum = (
                categoriesValues[defaultValue(distrib.entity)] || []
              ).reduce((partialSum, a) => partialSum + a, 0);
              if (categoriesValues[defaultValue(distrib.entity)]) {
                categoriesValues[defaultValue(distrib.entity)].push(
                  distrib.value - sum,
                );
              } else {
                categoriesValues[defaultValue(distrib.entity)] = [
                  distrib.value - sum,
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
            let subSectionIdsOrder = [];
            if (
              finalField === 'internal_id'
              && finalSubDistributionField === 'internal_id'
            ) {
              // find subbars orders for entity subbars redirection
              for (const distrib of props.stixRelationshipsDistribution) {
                for (const subDistrib of distrib.entity[key]) {
                  subSectionIdsOrder[subDistrib.label] = (subSectionIdsOrder[subDistrib.label] || 0)
                    + subDistrib.value;
                }
              }
              subSectionIdsOrder = R.take(
                subSelection.number ?? 15,
                Object.entries(subSectionIdsOrder)
                  .sort(([, a], [, b]) => b - a)
                  .map((k) => k[0]),
              );
            }
            const redirectionUtils = finalField === 'internal_id'
              ? props.stixRelationshipsDistribution.map((n) => ({
                id: n.label,
                entity_type: n.entity.entity_type,
                series: subSectionIdsOrder.map((subSectionId) => {
                  const [entity] = n.entity[key].filter(
                    (e) => e.label === subSectionId,
                  );
                  return {
                    id: subSectionId,
                    entity_type: entity ? entity.entity.entity_type : null,
                  };
                }),
              }))
              : null;
            return (
              <WidgetHorizontalBars
                series={chartData}
                distributed={parameters.distributed}
                withExport={withExportPopover}
                readonly={isReadOnly}
                redirectionUtils={redirectionUtils}
                stacked
                total
                legend
                categories={categories}
              />
            );
          }
          if (props) {
            return <WidgetNoData />;
          }
          return <WidgetLoader />;
        }}
      />
    );
  };
  return (
    <WidgetContainer
      height={height}
      title={parameters.title ?? title ?? t_i18n('Distribution of entities')}
      variant={variant}
    >
      {renderContent()}
    </WidgetContainer>
  );
};

export default StixRelationshipsMultiHorizontalBars;
