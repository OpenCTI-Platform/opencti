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
          ... on StixDomainObject {
            created
            modified
          }
          ... on AttackPattern {
            name
            description
          }
          ... on Campaign {
            name
            description
          }
          ... on Note {
            attribute_abstract
          }
          ... on Opinion {
            opinion
          }
          ... on ObservedData {
            first_observed
            last_observed
          }
          ... on Opinion {
            opinion
          }
          ... on Report {
            name
            description
            published
          }
          ... on Grouping {
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
          ... on Note {
            attribute_abstract
            content
          }
          ... on Opinion {
            opinion
          }
          ... on StixCyberObservable {
            observable_value
          }
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
