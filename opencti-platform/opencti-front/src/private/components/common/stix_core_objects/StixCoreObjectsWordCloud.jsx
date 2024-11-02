import React from 'react';
import { graphql } from 'react-relay';
import * as PropTypes from 'prop-types';
import { QueryRenderer } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetWordCloud from '../../../../components/dashboard/WidgetWordCloud';
import Loader, { LoaderVariant } from '../../../../components/Loader';

const stixCoreObjectsWordCloudDistributionQuery = graphql`
  query StixCoreObjectsWordCloudDistributionQuery(
    $objectId: [String]
    $relationship_type: [String]
    $toTypes: [String]
    $elementWithTargetTypes: [String]
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
      elementWithTargetTypes: $elementWithTargetTypes
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
        # use colors when available
        ... on Label {
          color
        }
        ... on MarkingDefinition {
          x_opencti_color
        }
        # objects without representative
        ... on Creator {
          name
        }
        ... on Group {
          name
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

const StixCoreObjectsWordCloud = ({
  variant,
  height,
  startDate,
  endDate,
  dataSelection,
  parameters = {},
}) => {
  const { t_i18n } = useFormatter();
  const renderContent = () => {
    const selection = dataSelection[0];
    const dataSelectionTypes = ['Stix-Core-Object'];
    const variables = {
      types: dataSelectionTypes,
      field: selection.attribute,
      operation: 'count',
      startDate,
      endDate,
      dateAttribute:
        selection.date_attribute && selection.date_attribute.length > 0
          ? selection.date_attribute
          : 'created_at',
      filters: selection.filters,
      limit: selection.number ?? 10,
    };
    return (
      <QueryRenderer
        query={stixCoreObjectsWordCloudDistributionQuery}
        variables={variables}
        render={({ props }) => {
          if (
            props
            && props.stixCoreObjectsDistribution
            && props.stixCoreObjectsDistribution.length > 0
          ) {
            return (
              <WidgetWordCloud data={props.stixCoreObjectsDistribution} groupBy={selection.attribute} />
            );
          }
          if (props) {
            return <WidgetNoData />;
          }
          return <Loader variant={LoaderVariant.inElement} />;
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

StixCoreObjectsWordCloud.propTypes = {
  variant: PropTypes.string,
  height: PropTypes.number,
  startDate: PropTypes.string,
  endDate: PropTypes.string,
  dataSelection: PropTypes.array,
  parameters: PropTypes.object,
};

export default StixCoreObjectsWordCloud;
