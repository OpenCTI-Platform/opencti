import React from 'react';
import { graphql } from 'react-relay';
import { QueryRenderer } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import { buildFiltersAndOptionsForWidgets } from '../../../../utils/filters/filtersUtils';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import WidgetLoader from '../../../../components/dashboard/WidgetLoader';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetTree from '../../../../components/dashboard/WidgetTree';

const stixCoreObjectsTreeMapDistributionQuery = graphql`
  query StixCoreObjectsTreeMapDistributionQuery(
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
        # objects without representative
        ... on Creator {
          name
        }
        ... on Status {
          template {
            name
          }
        }
      }
    }
  }
`;

const StixCoreObjectsTreeMap = ({
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
  const renderContent = () => {
    const selection = dataSelection[0];
    const dataSelectionTypes = ['Stix-Core-Object'];
    const { filters, dataSelectionElementId, dataSelectionToTypes } = buildFiltersAndOptionsForWidgets(selection.filters);
    return (
      <QueryRenderer
        query={stixCoreObjectsTreeMapDistributionQuery}
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
            const data = props.stixCoreObjectsDistribution;
            return (
              <WidgetTree
                data={data}
                groupBy={selection.attribute}
                isDistributed={parameters.distributed}
                readonly={isReadOnly}
                withExport={withExportPopover}
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

export default StixCoreObjectsTreeMap;
