import React from 'react';
import { graphql } from 'react-relay';
import { useTheme } from '@mui/styles';
import { QueryRenderer } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import { itemColor } from '../../../../utils/Colors';
import { defaultValue } from '../../../../utils/Graph';
import { buildFiltersAndOptionsForWidgets } from '../../../../utils/filters/filtersUtils';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import WidgetLoader from '../../../../components/dashboard/WidgetLoader';
import WidgetHorizontalBars from '../../../../components/dashboard/WidgetHorizontalBars';

const stixRelationshipsHorizontalBarsDistributionQuery = graphql`
  query StixRelationshipsHorizontalBarsDistributionQuery(
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
        ... on AttackPattern {
          name
          description
          x_mitre_id
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
`;

const StixRelationshipsHorizontalBars = ({
  title,
  variant,
  withoutTitle,
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
  const theme = useTheme();
  const { t_i18n } = useFormatter();
  const renderContent = () => {
    let selection = {};
    let filtersAndOptions;
    let dataSelectionDateAttribute = 'created_at';
    if (dataSelection) {
      // eslint-disable-next-line prefer-destructuring
      selection = dataSelection[0];
      filtersAndOptions = buildFiltersAndOptionsForWidgets(selection.filters);
      dataSelectionDateAttribute = selection.date_attribute && selection.date_attribute.length > 0
        ? selection.date_attribute
        : 'created_at';
    }
    const finalField = selection.attribute || field || 'entity_type';
    const variables = {
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
    return (
      <QueryRenderer
        query={stixRelationshipsHorizontalBarsDistributionQuery}
        variables={variables}
        render={({ props }) => {
          if (
            props
            && props.stixRelationshipsDistribution
            && props.stixRelationshipsDistribution.length > 0
          ) {
            const data = props.stixRelationshipsDistribution.map((n) => {
              let color = selection.attribute.endsWith('_id')
                ? itemColor(n.entity.entity_type)
                : itemColor(n.label);
              if (n.entity?.color) {
                color = theme.palette.mode === 'light' && n.entity.color === '#ffffff'
                  ? '#000000'
                  : n.entity.color;
              }
              if (n.entity?.x_opencti_color) {
                color = theme.palette.mode === 'light'
                && n.entity.x_opencti_color === '#ffffff'
                  ? '#000000'
                  : n.entity.x_opencti_color;
              }
              if (n.entity?.template?.color) {
                color = theme.palette.mode === 'light'
                && n.entity.template.color === '#ffffff'
                  ? '#000000'
                  : n.entity.template.color;
              }
              return {
                x: finalField.endsWith('_id')
                  ? defaultValue(n.entity)
                  : n.label,
                y: n.value,
                fillColor: color,
              };
            });
            const chartData = [{ name: t_i18n('Number of relationships'), data }];
            const redirectionUtils = finalField.endsWith('_id')
              ? props.stixRelationshipsDistribution.map((n) => ({
                id: n.label,
                entity_type: n.entity.entity_type,
              }))
              : undefined;
            return (
              <WidgetHorizontalBars
                series={chartData}
                distributed={parameters.distributed}
                withExport={withExportPopover}
                readonly={isReadOnly}
                redirectionUtils={redirectionUtils}
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
      withoutTitle={withoutTitle}
    >
      {renderContent()}
    </WidgetContainer>
  );
};

export default StixRelationshipsHorizontalBars;
