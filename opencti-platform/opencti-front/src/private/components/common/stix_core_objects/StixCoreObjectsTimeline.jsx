import React from 'react';
import { graphql } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import { QueryRenderer } from '../../../../relay/environment';
import { buildFiltersAndOptionsForWidgets } from '../../../../utils/filters/filtersUtils';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import WidgetLoader from '../../../../components/dashboard/WidgetLoader';
import WidgetTimeline from '../../../../components/dashboard/WidgetTimeline';
import { resolveLink } from '../../../../utils/Entity';

const stixCoreObjectsTimelineQuery = graphql`
  query StixCoreObjectsTimelineQuery(
    $types: [String]
    $first: Int
    $orderBy: StixCoreObjectsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
  ) {
    stixCoreObjects(
      types: $types
      first: $first
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) {
      edges {
        node {
          id
          entity_type
          created_at
          createdBy {
            ... on Identity {
              id
              name
              entity_type
            }
          }
          objectMarking {
            id
            definition_type
            definition
            x_opencti_order
            x_opencti_color
          }
          ... on BasicObject {
            id
            entity_type
          }
          ... on StixObject {
            representative {
              main
              secondary
            }
          }
          ... on StixDomainObject {
            created
            modified
          }
          ... on StixCyberObservable {
            observable_value
          }
        }
      }
    }
  }
`;

const StixCoreObjectsTimeline = ({
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
    const dateAttribute = selection.date_attribute && selection.date_attribute.length > 0
      ? selection.date_attribute
      : 'created_at';
    const { filters } = buildFiltersAndOptionsForWidgets(selection.filters, { startDate, endDate, dateAttribute });
    return (
      <QueryRenderer
        query={stixCoreObjectsTimelineQuery}
        variables={{
          types: dataSelectionTypes,
          first: selection.number ?? 10,
          orderBy: dateAttribute,
          orderMode: 'desc',
          filters,
        }}
        render={({ props }) => {
          if (
            props
            && props.stixCoreObjects
            && props.stixCoreObjects.edges.length > 0
          ) {
            const stixCoreObjectsEdges = props.stixCoreObjects.edges;
            const data = stixCoreObjectsEdges.map((stixCoreObjectEdge) => {
              const stixCoreObject = stixCoreObjectEdge.node;
              const link = `${resolveLink(stixCoreObject.entity_type)}/${stixCoreObject.id}`;
              return {
                value: stixCoreObject,
                link,
              };
            });
            return <WidgetTimeline data={data} />;
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
      title={parameters.title ?? t_i18n('Entities list')}
      variant={variant}
    >
      {renderContent()}
    </WidgetContainer>
  );
};

export default StixCoreObjectsTimeline;
