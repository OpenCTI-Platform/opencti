import React from 'react';
import { graphql } from 'react-relay';
import { QueryRenderer } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import { buildFiltersAndOptionsForWidgets } from '../../../../utils/filters/filtersUtils';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import WidgetLoader from '../../../../components/dashboard/WidgetLoader';
import WidgetHorizontalBars from '../../../../components/dashboard/WidgetHorizontalBars';
import useDistributionGraphData from '../../../../utils/hooks/useDistributionGraphData';

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
  const { t_i18n } = useFormatter();
  const { buildWidgetProps } = useDistributionGraphData();

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
            const { series, redirectionUtils } = buildWidgetProps(props.stixCoreObjectsDistribution, selection, 'Number of relationships');
            return (
              <WidgetHorizontalBars
                series={series}
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
