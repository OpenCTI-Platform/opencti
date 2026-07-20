import React, { ReactNode, useRef } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { getDefaultWidgetColumns } from '../../widgets/WidgetListsDefaultColumns';
import { useFormatter } from '../../../../components/i18n';
import { buildFiltersAndOptionsForWidgets, normalizeFilterGroupForBackend } from '../../../../utils/filters/filtersUtils';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import WidgetListCoreObjects from '../../../../components/dashboard/WidgetListCoreObjects';
import useDashboardViz from '../../../../components/dashboard/useDashboardViz';
import WidgetRenderContent from '../../../../components/dashboard/WidgetRenderContent';
import type { Widget, WidgetDataSelection, WidgetHost } from '../../../../utils/widget/widget';
import { OrderingMode, StixCoreObjectsListQuery, StixCoreObjectsOrdering } from '@components/common/stix_core_objects/__generated__/StixCoreObjectsListQuery.graphql';
import type { DashboardConfig } from '../../../../components/dashboard/dashboard-types';
import { computeStartEndDates } from '../../../../components/dashboard/dashboardVizUtils';

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
            x_opencti_score
            metrics {
              name
              value
            }
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
            x_opencti_cvss_v4_base_score
            x_opencti_cvss_v4_base_severity
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

interface StixCoreObjectsListComponentProps {
  rootRef: React.RefObject<HTMLDivElement | null>;
  queryRef: PreloadedQuery<StixCoreObjectsListQuery>;
  dataSelection: Widget['dataSelection'];
  widgetId: string;
}

const StixCoreObjectsListComponent = ({
  dataSelection,
  widgetId,
  rootRef,
  queryRef,
}: StixCoreObjectsListComponentProps) => {
  const data = usePreloadedQuery(stixCoreObjectsListQuery, queryRef);
  const selection = dataSelection[0];
  const columns = selection.columns ?? getDefaultWidgetColumns('entities');
  const edges = data?.stixCoreObjects?.edges ?? [];
  return edges.length === 0 ? (
    <WidgetNoData />
  ) : (
    <WidgetListCoreObjects
      data={edges}
      rootRef={rootRef.current ?? undefined}
      widgetId={widgetId}
      pageSize={selection.number ?? 10}
      columns={[...columns]}
    />
  );
};
interface StixCoreObjectsListProps {
  title?: string;
  variant?: string;
  height?: number;
  parameters: { title?: string };
  popover?: ReactNode;
  dataSelection: Widget['dataSelection'];
  widgetId: string;
  host?: WidgetHost;
  config: DashboardConfig;
  refreshRate?: number | null;
}

const DATA_SELECTION_TYPES = ['Stix-Core-Object'];

const buildQueryVariables = (resolvedDataSelection: WidgetDataSelection[], config: DashboardConfig) => {
  const selection = resolvedDataSelection[0];
  const orderBy = (selection.sort_by && selection.sort_by.length > 0
    ? selection.sort_by
    : 'created_at') as StixCoreObjectsOrdering | null | undefined;
  const dateAttribute = selection.date_attribute && selection.date_attribute.length > 0
    ? selection.date_attribute
    : 'created_at';
  const first = selection.number ?? 10;
  const orderMode = (selection.sort_mode ?? 'asc') as OrderingMode;
  const { startDate, endDate } = computeStartEndDates(config);
  const { filters } = buildFiltersAndOptionsForWidgets(
    selection.filters,
    { startDate, endDate, dateAttribute },
  );
  return {
    types: DATA_SELECTION_TYPES,
    first,
    orderBy,
    orderMode,
    filters: normalizeFilterGroupForBackend(filters),
  };
};

const StixCoreObjectsList = ({
  height,
  parameters,
  variant,
  popover,
  title,
  dataSelection,
  widgetId,
  config,
  refreshRate = null,
  host,
}: StixCoreObjectsListProps) => {
  const { t_i18n } = useFormatter();
  const rootRef = useRef<HTMLDivElement>(null);
  const { resolvedDataSelection, isMissingHostEntity, isMissingSavedFilters, isPreviewMode, queryRef } = useDashboardViz<StixCoreObjectsListQuery>({
    perspective: 'entities',
    dataSelection,
    host,
    refreshRate,
    query: stixCoreObjectsListQuery,
    config,
    buildQueryVariables,
  });

  return (
    <WidgetContainer
      padding="horizontal"
      height={height}
      title={parameters?.title ?? title ?? t_i18n('Entities list')}
      variant={variant}
      action={popover}
      showPreviewTag={isPreviewMode}
    >
      <div ref={rootRef} style={{ height: '100%' }}>
        <WidgetRenderContent
          isMissingHostEntity={isMissingHostEntity}
          isMissingSavedFilters={isMissingSavedFilters}
          queryRef={queryRef}
          host={host}
        >
          <StixCoreObjectsListComponent
            queryRef={queryRef!}
            rootRef={rootRef}
            dataSelection={resolvedDataSelection}
            widgetId={widgetId}
          />
        </WidgetRenderContent>
      </div>
    </WidgetContainer>
  );
};

export default StixCoreObjectsList;
