import React from 'react';
import { graphql } from 'react-relay';
import { QueryRenderer } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import { getMainRepresentative, isFieldForIdentifier } from '../../../../utils/defaultRepresentatives';
import useGranted, { SETTINGS_SETACCESSES } from '../../../../utils/hooks/useGranted';
import { buildFiltersAndOptionsForWidgets } from '../../../../utils/filters/filtersUtils';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetDistributionList from '../../../../components/dashboard/WidgetDistributionList';
import Loader, { LoaderVariant } from '../../../../components/Loader';

const stixRelationshipsDistributionListDistributionQuery = graphql`
  query StixRelationshipsDistributionListDistributionQuery(
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
        # objects without representative
        ... on Creator {
          name
        }
        ... on Group {
          name
        }
        ... on Workspace {
          name
          type
        }
      }
    }
  }
`;

const StixRelationshipsDistributionList = ({
  title,
  variant,
  overflow,
  height,
  field,
  startDate,
  endDate,
  dataSelection,
  parameters = {},
}) => {
  const { t_i18n } = useFormatter();
  const hasSetAccess = useGranted([SETTINGS_SETACCESSES]);
  const renderContent = () => {
    let selection = {};
    let filtersAndOptions;
    if (dataSelection) {
      selection = dataSelection[0];
      filtersAndOptions = buildFiltersAndOptionsForWidgets(selection.filters, { isKnowledgeRelationshipWidget: true });
    }
    const finalField = selection.attribute || field || 'entity_type';
    const variables = {
      field: finalField,
      operation: 'count',
      startDate,
      endDate,
      dateAttribute: selection.date_attribute ?? 'created_at',
      limit: selection.number ?? 10,
      filters: filtersAndOptions?.filters,
      isTo: selection.isTo,
      dynamicFrom: selection.dynamicFrom,
      dynamicTo: selection.dynamicTo,
    };

    return (
      <QueryRenderer
        query={stixRelationshipsDistributionListDistributionQuery}
        variables={variables}
        render={({ props }) => {
          if (
            props
            && props.stixRelationshipsDistribution
            && props.stixRelationshipsDistribution.length > 0
          ) {
            const data = props.stixRelationshipsDistribution.map((n) => {
              let { label } = n;
              let id = null;
              let type = n.label;
              if (isFieldForIdentifier(finalField)) {
                label = getMainRepresentative(n.entity);
                id = n.entity?.id;
                type = n.entity?.entity_type;
              }
              return {
                label,
                value: n.value,
                id,
                type,
              };
            });
            return (
              <WidgetDistributionList
                data={data}
                hasSettingAccess={hasSetAccess}
                overflow={overflow}
              />
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
      title={parameters.title ?? title ?? t_i18n('Relationships distribution')}
      variant={variant}
    >
      {renderContent()}
    </WidgetContainer>
  );
};

export default StixRelationshipsDistributionList;
