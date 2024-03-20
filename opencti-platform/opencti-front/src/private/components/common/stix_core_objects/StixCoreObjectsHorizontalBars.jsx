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

const stixCoreObjectsHorizontalBarsDistributionQuery = graphql`
    query StixCoreObjectsHorizontalBarsDistributionQuery(
        $objectId: [String]
        $relationship_type: [String]
        $toTypes: [String]
        $field: String!
        $startDate: DateTime
        $endDate: DateTime
        $dateAttribute: String
        $operation: StatsOperation!
        $limit: Int
        $order: String
        $types: [String]
        $filters: FilterGroup
        $search: String
    ) {
        stixCoreObjectsDistribution(
            objectId: $objectId
            relationship_type: $relationship_type
            toTypes: $toTypes
            field: $field
            startDate: $startDate
            endDate: $endDate
            dateAttribute: $dateAttribute
            operation: $operation
            limit: $limit
            order: $order
            types: $types
            filters: $filters
            search: $search
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
                ... on MalwareAnalysis {
                    result_name
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
                    x_opencti_color
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

const StixCoreObjectsHorizontalBars = ({
  variant,
  height,
  startDate,
  endDate,
  dataSelection,
  parameters = {},
  withExportPopover = false,
  isReadOnly = false,
}) => {
  const theme = useTheme();
  const { t_i18n } = useFormatter();
  const renderContent = () => {
    const selection = dataSelection[0];
    const dataSelectionTypes = ['Stix-Core-Object'];
    const { filters, dataSelectionElementId, dataSelectionToTypes } = buildFiltersAndOptionsForWidgets(selection.filters);
    return (
      <QueryRenderer
        query={stixCoreObjectsHorizontalBarsDistributionQuery}
        variables={{
          objectId: dataSelectionElementId,
          toTypes: dataSelectionToTypes,
          types: dataSelectionTypes,
          field: selection.attribute,
          operation: 'count',
          startDate,
          endDate,
          dateAttribute:
            selection.date_attribute && selection.date_attribute.length > 0
              ? selection.date_attribute
              : 'created_at',
          filters,
          limit: selection.number ?? 10,
        }}
        render={({ props }) => {
          if (
            props
            && props.stixCoreObjectsDistribution
            && props.stixCoreObjectsDistribution.length > 0
          ) {
            const data = props.stixCoreObjectsDistribution.map((n) => {
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
                // eslint-disable-next-line no-nested-ternary
                x: selection.attribute.endsWith('_id')
                  ? defaultValue(n.entity)
                  : selection.attribute === 'entity_type'
                    ? t_i18n(`entity_${n.label}`)
                    : n.label,
                y: n.value,
                fillColor: color,
              };
            });
            const chartData = [
              {
                name: selection.label || t_i18n('Number of relationships'),
                data,
              },
            ];
            const redirectionUtils = selection.attribute === 'name'
              ? props.stixCoreObjectsDistribution.map((n) => ({
                id: n.entity.id,
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
      title={parameters.title ?? t_i18n('Distribution of entities')}
      variant={variant}
    >
      {renderContent()}
    </WidgetContainer>
  );
};

export default StixCoreObjectsHorizontalBars;
