import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import React, { useRef } from 'react';
import { getDefaultWidgetColumns } from '@components/widgets/WidgetListsDefaultColumns';
import WidgetListCoreObjects from '../../../../components/dashboard/WidgetListCoreObjects';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import type { PublicWidgetContainerProps } from '../PublicWidgetContainerProps';
import { useFormatter } from '../../../../components/i18n';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import { PublicStixCoreObjectsListQuery } from './__generated__/PublicStixCoreObjectsListQuery.graphql';
import { DataTableProps } from '../../../../components/dataGrid/dataTableTypes';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import type { WidgetColumn } from '../../../../utils/widget/widget';

const publicStixCoreObjectsListQuery = graphql`
  query PublicStixCoreObjectsListQuery(
    $startDate: DateTime
    $endDate: DateTime
    $uriKey: String!
    $widgetId : String!
  ) {
    publicStixCoreObjects(
      startDate: $startDate
      endDate: $endDate
      uriKey: $uriKey
      widgetId : $widgetId
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
          creators {
            id
            name
          }
          ... on StixDomainObject {
            created
            modified
          }
          ... on AttackPattern {
            name
            description
            modified
            x_mitre_id
            aliases
          }
          ... on Note {
            note_types
            modified
          }
          ... on Campaign {
            name
            description
            modified
            aliases
          }
          ... on Note {
            attribute_abstract
            modified
          }
          ... on ObservedData {
            name
            modified
            first_observed
            last_observed
          }
          ... on Opinion {
            opinion
            modified
          }
          ... on Report {
            name
            description
            modified
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
            modified
            x_opencti_aliases
            context
          }
          ... on CourseOfAction {
            name
            description
            modified
            x_opencti_aliases
            x_mitre_id
          }
          ... on Individual {
            name
            description
            modified
            x_opencti_aliases
          }
          ... on Organization {
            name
            description
            modified
            x_opencti_aliases
            x_opencti_organization_type
          }
          ... on Sector {
            name
            description
            modified
            x_opencti_aliases
          }
          ... on System {
            name
            description
            modified
            x_opencti_aliases
          }
          ... on Indicator {
            name
            description
            modified
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
            modified
            aliases
          }
          ... on IntrusionSet {
            name
            description
            modified
            aliases
            resource_level
          }
          ... on Position {
            name
            description
            modified
            x_opencti_aliases
          }
          ... on City {
            name
            description
            modified
            x_opencti_aliases
          }
          ... on AdministrativeArea {
            name
            description
            modified
            x_opencti_aliases
          }
          ... on Country {
            name
            description
            modified
            x_opencti_aliases
          }
          ... on Region {
            name
            description
            modified
            x_opencti_aliases
          }
          ... on Malware {
            name
            description
            modified
            malware_types
            aliases
          }
          ... on MalwareAnalysis {
            result_name
            product
            modified
            objectAssignee {
              entity_type
              id
              name
            }
          }
          ... on ThreatActor {
            name
            description
            modified
            aliases
            threat_actor_types
          }
          ... on ThreatActorGroup {
            threat_actor_types
            modified
            aliases
          }
          ... on ThreatActorIndividual {
            threat_actor_types
            modified
            aliases
          }
          ... on Tool {
            name
            description
            modified
            tool_types
            aliases
          }
          ... on Vulnerability {
            name
            description
            modified
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
            modified
            incident_type
            severity
            aliases
          }
          ... on Event {
            name
            description
            modified
            event_types
            aliases
          }
          ... on Channel {
            name
            description
            modified
            channel_types
            aliases
          }
          ... on Narrative {
            name
            description
            modified
            aliases
          }
          ... on Language {
            name
            modified
            aliases
          }
          ... on DataComponent {
            name
            modified
            aliases
          }
          ... on DataSource {
            name
            modified
            aliases
          }
          ... on Task {
            name
            description
            modified
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
            modified
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
            modified
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
            modified
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
            modified
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
            modified
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
            modified
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

interface PublicStixCoreObjectsListComponentProps {
  queryRef: PreloadedQuery<PublicStixCoreObjectsListQuery>
  rootRef: DataTableProps['rootRef']
  widgetId: string
  columns: WidgetColumn[]
}

const PublicStixCoreObjectsListComponent = ({
  queryRef,
  rootRef,
  widgetId,
  columns,
}: PublicStixCoreObjectsListComponentProps) => {
  const { publicStixCoreObjects } = usePreloadedQuery(
    publicStixCoreObjectsListQuery,
    queryRef,
  );

  if (publicStixCoreObjects?.edges && publicStixCoreObjects.edges.length > 0) {
    return (
      <WidgetListCoreObjects
        data={[...publicStixCoreObjects.edges]}
        publicWidget
        rootRef={rootRef}
        widgetId={widgetId}
        pageSize={100}
        columns={columns}
      />
    );
  }
  return <WidgetNoData />;
};

PublicStixCoreObjectsListComponent.displayName = 'PublicStixCoreObjectsListComponent';

const PublicStixCoreObjectsList = ({
  uriKey,
  widget,
  startDate,
  endDate,
  title,
}: PublicWidgetContainerProps) => {
  const { t_i18n } = useFormatter();
  const { id, parameters, dataSelection } = widget;
  const queryRef = useQueryLoading<PublicStixCoreObjectsListQuery>(
    publicStixCoreObjectsListQuery,
    {
      uriKey,
      widgetId: id,
      startDate,
      endDate,
    },
  );

  const selection = dataSelection[0];
  const columns = selection.columns ?? getDefaultWidgetColumns('entities');

  const rootRef = useRef<HTMLDivElement>(null);

  return (
    <WidgetContainer
      title={parameters?.title ?? title ?? t_i18n('Entities number')}
      variant="inLine"
    >
      <div ref={rootRef} style={{ height: '100%' }}>
        {queryRef ? (
          <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
            <PublicStixCoreObjectsListComponent
              queryRef={queryRef}
              columns={[...columns]}
              rootRef={rootRef.current ?? undefined}
              widgetId={id}
            />
          </React.Suspense>
        ) : (
          <Loader variant={LoaderVariant.inElement} />
        )}
      </div>
    </WidgetContainer>
  );
};

export default PublicStixCoreObjectsList;
