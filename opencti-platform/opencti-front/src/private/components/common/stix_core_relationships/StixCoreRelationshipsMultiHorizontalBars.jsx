import React from 'react';
import { graphql } from 'react-relay';
import CircularProgress from '@mui/material/CircularProgress';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import makeStyles from '@mui/styles/makeStyles';
import { useTheme } from '@mui/styles';
import * as R from 'ramda';
import { useNavigate } from 'react-router-dom-v5-compat';
import Chart from '../charts/Chart';
import { QueryRenderer } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import { horizontalBarsChartOptions } from '../../../../utils/Charts';
import { simpleNumberFormat } from '../../../../utils/Number';
import { convertFilters } from '../../../../utils/ListParameters';
import { defaultValue } from '../../../../utils/Graph';

const useStyles = makeStyles(() => ({
  paper: {
    height: '100%',
    margin: '10px 0 0 0',
    padding: 0,
    borderRadius: 6,
  },
}));

const stixCoreRelationshipsMultiHorizontalBarsWithRelationshipsDistributionQuery = graphql`
  query StixCoreRelationshipsMultiHorizontalBarsWithRelationshipsDistributionQuery(
    $field: String!
    $operation: StatsOperation!
    $startDate: DateTime
    $endDate: DateTime
    $dateAttribute: String
    $isTo: Boolean
    $limit: Int
    $elementId: [String]
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
    $filters: [StixCoreRelationshipsFiltering]
    $filterMode: FilterMode
    $dynamicFrom: [StixCoreObjectsFiltering]
    $dynamicTo: [StixCoreObjectsFiltering]
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
    $subDistributionFilters: [StixCoreRelationshipsFiltering]
    $subDistributionFilterMode: FilterMode
  ) {
    stixCoreRelationshipsDistribution(
      field: $field
      operation: $operation
      startDate: $startDate
      endDate: $endDate
      dateAttribute: $dateAttribute
      isTo: $isTo
      limit: $limit
      elementId: $elementId
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
      filterMode: $filterMode
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
            filterMode: $subDistributionFilterMode
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
              ... on ThreatActorGroup {
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
        ... on ThreatActorGroup {
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

const stixCoreRelationshipsMultiHorizontalBarsWithEntitiesDistributionQuery = graphql`
  query StixCoreRelationshipsMultiHorizontalBarsWithEntitiesDistributionQuery(
    $field: String!
    $operation: StatsOperation!
    $startDate: DateTime
    $endDate: DateTime
    $dateAttribute: String
    $isTo: Boolean
    $limit: Int
    $elementId: [String]
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
    $filters: [StixCoreRelationshipsFiltering]
    $filterMode: FilterMode
    $dynamicFrom: [StixCoreObjectsFiltering]
    $dynamicTo: [StixCoreObjectsFiltering]
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
    $subDistributionFilters: [StixCoreObjectsFiltering]
    $subDistributionFilterMode: FilterMode
    $subDistributionSearch: String
  ) {
    stixCoreRelationshipsDistribution(
      field: $field
      operation: $operation
      startDate: $startDate
      endDate: $endDate
      dateAttribute: $dateAttribute
      isTo: $isTo
      limit: $limit
      elementId: $elementId
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
      filterMode: $filterMode
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
            filterMode: $subDistributionFilterMode
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
              ... on ThreatActorGroup {
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
        ... on ThreatActorGroup {
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

const StixCoreRelationshipsMultiHorizontalBars = ({
  title,
  variant,
  height,
  stixCoreObjectId,
  relationshipType,
  toTypes,
  field,
  startDate,
  endDate,
  dateAttribute,
  dataSelection,
  parameters = {},
  withExportPopover = false,
}) => {
  const classes = useStyles();
  const theme = useTheme();
  const { t } = useFormatter();
  const navigate = useNavigate();
  const renderContent = () => {
    let finalFilters = [];
    let selection = {};
    let dataSelectionDateAttribute = null;
    let dataSelectionRelationshipType = null;
    let dataSelectionFromId = null;
    let dataSelectionToId = null;
    let dataSelectionFromTypes = null;
    let dataSelectionToTypes = null;
    let subSelection = {};
    let subDistributionTypes = null;
    let subSelectionFinalFilters = [];
    let subDistributionRelationshipType = null;
    let subDistributionToTypes = null;
    let subSelectionRelationshipType = null;
    let subSelectionFromId = null;
    let subSelectionToId = null;
    let subSelectionFromTypes = null;
    let subSelectionToTypes = null;
    if (dataSelection) {
      // eslint-disable-next-line prefer-destructuring
      selection = dataSelection[0];
      finalFilters = convertFilters(selection.filters);
      dataSelectionDateAttribute = selection.date_attribute && selection.date_attribute.length > 0
        ? selection.date_attribute
        : 'created_at';
      dataSelectionRelationshipType = R.head(finalFilters.filter((n) => n.key === 'relationship_type'))
        ?.values || null;
      dataSelectionFromId = R.head(finalFilters.filter((n) => n.key === 'fromId'))?.values || null;
      dataSelectionToId = R.head(finalFilters.filter((n) => n.key === 'toId'))?.values || null;
      dataSelectionFromTypes = R.head(finalFilters.filter((n) => n.key === 'fromTypes'))?.values
        || null;
      dataSelectionToTypes = R.head(finalFilters.filter((n) => n.key === 'toTypes'))?.values || null;
      finalFilters = finalFilters.filter(
        (n) => ![
          'relationship_type',
          'fromId',
          'toId',
          'fromTypes',
          'toTypes',
        ].includes(n.key),
      );
      if (dataSelection.length > 1) {
        // eslint-disable-next-line prefer-destructuring
        subSelection = dataSelection[1];
        subSelectionFinalFilters = convertFilters(subSelection.filters);
        if (subSelection.perspective === 'entities') {
          subDistributionTypes = R.head(
            subSelectionFinalFilters.filter((n) => n.key === 'entity_type'),
          )?.values || ['Stix-Core-Object'];
          subDistributionRelationshipType = R.head(
            subSelectionFinalFilters.filter(
              (n) => n.key === 'relationship_type',
            ),
          )?.values || null;
          subDistributionToTypes = R.head(subSelectionFinalFilters.filter((n) => n.key === 'toTypes'))
            ?.values || null;
          subSelectionFinalFilters = subSelectionFinalFilters.filter(
            (n) => !['entity_type', 'relationship_type', 'toTypes'].includes(n.key),
          );
        } else {
          subSelectionRelationshipType = R.head(
            subSelectionFinalFilters.filter(
              (n) => n.key === 'relationship_type',
            ),
          )?.values || null;
          subSelectionFromId = R.head(subSelectionFinalFilters.filter((n) => n.key === 'fromId'))
            ?.values || null;
          subSelectionToId = R.head(subSelectionFinalFilters.filter((n) => n.key === 'toId'))
            ?.values || null;
          subSelectionFromTypes = R.head(
            subSelectionFinalFilters.filter((n) => n.key === 'fromTypes'),
          )?.values || null;
          subSelectionToTypes = R.head(subSelectionFinalFilters.filter((n) => n.key === 'toTypes'))
            ?.values || null;
          subSelectionFinalFilters = subSelectionFinalFilters.filter(
            (n) => !['fromId', 'toId', 'fromTypes', 'toTypes'].includes(n.key),
          );
        }
      }
    }
    const finalField = selection.attribute || field || 'entity_type';
    let variables = {
      fromId: dataSelectionFromId || stixCoreObjectId,
      toId: dataSelectionToId,
      relationship_type: dataSelectionRelationshipType || relationshipType,
      fromTypes: dataSelectionFromTypes,
      toTypes: dataSelectionToTypes || toTypes,
      field: finalField,
      operation: 'count',
      startDate,
      endDate,
      dateAttribute: dateAttribute || dataSelectionDateAttribute,
      limit: selection.number ?? 10,
      filters: finalFilters,
      isTo: selection.isTo,
      dynamicFrom: convertFilters(selection.dynamicFrom),
      dynamicTo: convertFilters(selection.dynamicTo),
    };
    const finalSubDistributionField = subSelection.attribute || field || 'entity_type';
    if (subSelection.perspective === 'entities') {
      variables = {
        ...variables,
        subDistributionRelationshipType,
        subDistributionToTypes,
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
        subDistributionFilters: subSelectionFinalFilters,
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
        subDistributionFromId: subSelectionFromId,
        subDistributionFromTypes: subSelectionFromTypes,
        subDistributionToId: subSelectionToId,
        subDistributionToTypes: subSelectionToTypes,
        subDistributionRelationshipType: subSelectionRelationshipType,
      };
    }
    return (
      <QueryRenderer
        query={
          subSelection.perspective === 'entities'
            ? stixCoreRelationshipsMultiHorizontalBarsWithEntitiesDistributionQuery
            : stixCoreRelationshipsMultiHorizontalBarsWithRelationshipsDistributionQuery
        }
        variables={variables}
        render={({ props }) => {
          const key = subSelection.perspective === 'entities'
            ? 'stixCoreObjectsDistribution'
            : 'stixCoreRelationshipsDistribution';
          if (
            props
            && props.stixCoreRelationshipsDistribution
            && props.stixCoreRelationshipsDistribution.length > 0
          ) {
            const categories = props.stixCoreRelationshipsDistribution.map(
              (n) => defaultValue(n.entity),
            );
            const entitiesMapping = {};
            for (const distrib of props.stixCoreRelationshipsDistribution) {
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
            for (const distrib of props.stixCoreRelationshipsDistribution) {
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
              for (const distrib of props.stixCoreRelationshipsDistribution) {
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
              ? props.stixCoreRelationshipsDistribution.map((n) => ({
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
              <Chart
                options={horizontalBarsChartOptions(
                  theme,
                  true,
                  simpleNumberFormat,
                  null,
                  false,
                  navigate,
                  redirectionUtils,
                  true,
                  true,
                  categories,
                  true,
                )}
                series={chartData}
                type="bar"
                width="100%"
                height="100%"
                withExportPopover={withExportPopover}
              />
            );
          }
          if (props) {
            return (
              <div style={{ display: 'table', height: '100%', width: '100%' }}>
                <span
                  style={{
                    display: 'table-cell',
                    verticalAlign: 'middle',
                    textAlign: 'center',
                  }}
                >
                  {t('No entities of this type has been found.')}
                </span>
              </div>
            );
          }
          return (
            <div style={{ display: 'table', height: '100%', width: '100%' }}>
              <span
                style={{
                  display: 'table-cell',
                  verticalAlign: 'middle',
                  textAlign: 'center',
                }}
              >
                <CircularProgress size={40} thickness={2} />
              </span>
            </div>
          );
        }}
      />
    );
  };
  return (
    <div style={{ height: height || '100%' }}>
      <Typography
        variant="h4"
        gutterBottom={true}
        style={{
          margin: variant !== 'inLine' ? '0 0 10px 0' : '-10px 0 10px -7px',
        }}
      >
        {parameters.title || title || t('Relationships DISTRIBUTION')}
      </Typography>
      {variant !== 'inLine' ? (
        <Paper classes={{ root: classes.paper }} variant="outlined">
          {renderContent()}
        </Paper>
      ) : (
        renderContent()
      )}
    </div>
  );
};

export default StixCoreRelationshipsMultiHorizontalBars;
