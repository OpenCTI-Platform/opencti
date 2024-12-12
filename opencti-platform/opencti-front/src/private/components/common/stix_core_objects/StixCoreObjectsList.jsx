import React, { useRef } from 'react';
import { graphql } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import { QueryRenderer } from '../../../../relay/environment';
import { buildFiltersAndOptionsForWidgets } from '../../../../utils/filters/filtersUtils';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import WidgetListCoreObjects from '../../../../components/dashboard/WidgetListCoreObjects';
import Loader, { LoaderVariant } from '../../../../components/Loader';

export const stixCoreObjectsListQuery = graphql`
  query StixCoreObjectsListQuery(
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
          representative {
            main
          }
          opinions_metrics {
            mean
            min
            max
            total
          }
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
          ... on ObservedData {
            name
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
            x_opencti_aliases
          }
          ... on Organization {
            name
            description
            x_opencti_aliases
          }
          ... on Sector {
            name
            description
          }
          ... on System {
            name
            description
            x_opencti_aliases
          }
          ... on Indicator {
            name
            description
            indicator_types
            pattern
            pattern_type
            valid_from
            valid_until
          }
          ... on Infrastructure {
            name
            description
          }
          ... on IntrusionSet {
            name
            description
            aliases
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
            aliases
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
          ... on Task {
            name
            description
            due_date
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
          objectLabel {
            id
            value
            color
          }
          objectMarking {
            id
            definition_type
            definition
            x_opencti_order
            x_opencti_color
          }
          ... on StixDomainObject {
            status {
              id
              order
              template {
                name
                color
              }
            }
            workflowEnabled
          }
        }
      }
    }
  }
`;

const StixCoreObjectsList = ({
  title,
  variant,
  height,
  startDate,
  endDate,
  dataSelection,
  widgetId,
  parameters = {},
}) => {
  const { t_i18n } = useFormatter();
  const selection = dataSelection[0];
  const dataSelectionTypes = ['Stix-Core-Object'];
  const sortBy = selection.sort_by && selection.sort_by.length > 0
    ? selection.sort_by
    : 'created_at';
  const dateAttribute = selection.date_attribute && selection.date_attribute.length > 0
    ? selection.date_attribute
    : 'created_at';
  const { filters } = buildFiltersAndOptionsForWidgets(selection.filters, { startDate, endDate, dateAttribute });

  const rootRef = useRef(null);

  return (
    <WidgetContainer
      height={height}
      title={parameters.title ?? title ?? t_i18n('Entities list')}
      variant={variant}
      ref={rootRef}
    >
      <QueryRenderer
        query={stixCoreObjectsListQuery}
        variables={{
          types: dataSelectionTypes,
          first: selection.number ?? 10,
          orderBy: sortBy,
          orderMode: selection.sort_mode ?? 'desc',
          filters,
        }}
        render={({ props }) => {
          if (
            props
            && props.stixCoreObjects
            && props.stixCoreObjects.edges.length > 0
          ) {
            const data = props.stixCoreObjects.edges;
            return (
              <WidgetListCoreObjects
                data={data}
                dateAttribute={dateAttribute}
                rootRef={rootRef.current ?? undefined}
                widgetId={widgetId}
                pageSize={selection.number ?? 10}
                sortBy={sortBy}
              />
            );
          }
          if (props) {
            return <WidgetNoData />;
          }
          return <Loader variant={LoaderVariant.inElement} />;
        }}
      />
    </WidgetContainer>
  );
};

export default StixCoreObjectsList;
