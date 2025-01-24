import React, { useRef } from 'react';
import { graphql } from 'react-relay';
import { getDefaultWidgetColumns } from '../../widgets/WidgetListsDefaultColumns';
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
            secondary
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
            x_mitre_id
            aliases
          }
          ... on Note {
            note_types
          }
          ... on Campaign {
            name
            description
            aliases
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
            report_types
            objectAssignee {
              entity_type
              id
              name
            }
            objectParticipant {
              entity_type
              id
              name
            }
          }
          ... on Grouping {
            name
            description
            x_opencti_aliases
            context
          }
          ... on CourseOfAction {
            name
            description
            x_opencti_aliases
            x_mitre_id
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
            x_opencti_organization_type
          }
          ... on Sector {
            name
            description
            x_opencti_aliases
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
            x_opencti_score
          }
          ... on Infrastructure {
            name
            description
            aliases
          }
          ... on IntrusionSet {
            name
            description
            aliases
            resource_level
          }
          ... on Position {
            name
            description
            x_opencti_aliases
          }
          ... on City {
            name
            description
            x_opencti_aliases
          }
          ... on AdministrativeArea {
            name
            description
            x_opencti_aliases
          }
          ... on Country {
            name
            description
            x_opencti_aliases
          }
          ... on Region {
            name
            description
            x_opencti_aliases
          }
          ... on Malware {
            name
            description
            malware_types
            aliases
          }
          ... on MalwareAnalysis {
            result_name
            product
            objectAssignee {
              entity_type
              id
              name
            }
          }
          ... on ThreatActor {
            name
            description
            aliases
            threat_actor_types
          }
          ... on ThreatActorGroup {
            threat_actor_types
            aliases
          }
          ... on ThreatActorIndividual {
            threat_actor_types
            aliases
          }
          ... on Tool {
            name
            description
            tool_types
            aliases
          }
          ... on Vulnerability {
            name
            description
            x_opencti_aliases
            x_opencti_cvss_base_score
            x_opencti_cvss_base_severity
            x_opencti_cisa_kev
            x_opencti_epss_score
            x_opencti_epss_percentile
          }
          ... on Incident {
            name
            description
            incident_type
            severity
            aliases
          }
          ... on Event {
            name
            description
            event_types
            aliases
          }
          ... on Channel {
            name
            description
            channel_types
            aliases
          }
          ... on Narrative {
            name
            description
            aliases
          }
          ... on Language {
            name
            aliases
          }
          ... on DataComponent {
            name
            aliases
          }
          ... on DataSource {
            name
            aliases
          }
          ... on Task {
            name
            description
            due_date
            objectAssignee {
              id
              name
              entity_type
            }
            objectParticipant {
              id
              name
              entity_type
            }
          }
          ... on Case {
            name
            objectAssignee {
              id
              name
              entity_type
            }
            objectParticipant {
              id
              name
              entity_type
            }
          }
          ... on CaseIncident {
            priority
            severity
            response_types
            objectAssignee {
              id
              name
              entity_type
            }
            objectParticipant {
              id
              name
              entity_type
            }
          }
          ... on CaseRfi {
            priority
            severity
            information_types
            objectAssignee {
              id
              name
              entity_type
            }
            objectParticipant {
              id
              name
              entity_type
            }
          }
          ... on CaseRft {
            priority
            severity
            takedown_types
            objectAssignee {
              id
              name
              entity_type
            }
            objectParticipant {
              id
              name
              entity_type
            }
          }
          ... on Task {
            name
            description
            due_date
          }
          ... on StixCyberObservable {
            observable_value
            x_opencti_description
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
  const columns = selection.columns ?? getDefaultWidgetColumns('entities');
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
    >
      <div ref={rootRef} style={{ height: '100%' }}>
        <QueryRenderer
          query={stixCoreObjectsListQuery}
          variables={{
            types: dataSelectionTypes,
            first: selection.number ?? 10,
            orderBy: sortBy,
            orderMode: selection.sort_mode ?? 'asc',
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
                  rootRef={rootRef.current ?? undefined}
                  widgetId={widgetId}
                  pageSize={selection.number ?? 10}
                  columns={columns}
                />
              );
            }
            if (props) {
              return <WidgetNoData />;
            }
            return <Loader variant={LoaderVariant.inElement} />;
          }}
        />
      </div>
    </WidgetContainer>
  );
};

export default StixCoreObjectsList;
