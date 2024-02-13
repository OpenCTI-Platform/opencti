import React from 'react';
import { graphql } from 'react-relay';
import { QueryRenderer } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import { dayAgo } from '../../../../utils/Time';
import { buildFiltersAndOptionsForWidgets } from '../../../../utils/filters/filtersUtils';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import WidgetLoader from '../../../../components/dashboard/WidgetLoader';
import WidgetNumber from '../../../../components/dashboard/WidgetNumber';

const stixRelationshipsNumberNumberQuery = graphql`
  query StixRelationshipsNumberNumberSeriesQuery(
    $dateAttribute: String
    $noDirection: Boolean
    $endDate: DateTime
    $onlyInferred: Boolean
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
    stixRelationshipsNumber(
      dateAttribute: $dateAttribute
      noDirection: $noDirection
      endDate: $endDate
      onlyInferred: $onlyInferred
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
      total
      count
    }
  }
`;

const StixRelationshipsNumber = ({
  variant,
  height,
  startDate,
  dataSelection,
  parameters = {},
}) => {
  const { t_i18n } = useFormatter();
  const renderContent = () => {
    const selection = dataSelection[0];
    const dateAttribute = selection.date_attribute && selection.date_attribute.length > 0
      ? selection.date_attribute
      : 'created_at';
    const { filters } = buildFiltersAndOptionsForWidgets(selection.filters);
    return (
      <QueryRenderer
        query={stixRelationshipsNumberNumberQuery}
        variables={{
          filters,
          startDate,
          dateAttribute,
          endDate: dayAgo(),
          dynamicFrom: selection.dynamicFrom,
          dynamicTo: selection.dynamicTo,
        }}
        render={({ props }) => {
          if (props && props.stixRelationshipsNumber) {
            const { total, count } = props.stixRelationshipsNumber;
            return <WidgetNumber total={total} value={count} />;
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
      title={parameters.title ?? t_i18n('Entities number')}
      variant={variant}
    >
      {renderContent()}
    </WidgetContainer>
  );
};

export default StixRelationshipsNumber;
