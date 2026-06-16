import React, { useRef } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { WidgetColumn, WidgetDataSelection, WidgetHost, type WidgetParameters } from '../../../../utils/widget/widget';
import { useFormatter } from '../../../../components/i18n';
import { WidgetColumnsLayout } from '@components/widgets/WidgetCustomAttributesColumnsInput';
import WidgetContainer from '../../../../components/dashboard/WidgetContainer';
import WidgetNoHostEntity from '../../../../components/dashboard/WidgetNoHostEntity';
import WidgetCustomAttributes from '@components/widgets/WidgetCustomAttribute';
import WidgetNoData from '../../../../components/dashboard/WidgetNoData';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { getCustomAttributesColumns } from '@components/widgets/WidgetListsDefaultColumns';
import { StixCoreObjectsCustomAttributesQuery } from '@components/common/stix_core_objects/__generated__/StixCoreObjectsCustomAttributesQuery.graphql';

export const stixCoreObjectsCustomAttributesQuery = graphql`
  query StixCoreObjectsCustomAttributesQuery($id: String!) {
    stixCoreObject(id: $id) {
      id
      entity_type
      created_at
      creators {
        id
        name
      }
      ... on StixDomainObject {
        created
        modified
        confidence
        revoked
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
      ... on Report {
        name
        description
        report_types
        content
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
      ... on Grouping {
        name
        description
        context
        content
      }
      ... on Campaign {
        name
        description
        objective
        first_seen
        last_seen
      }
      ... on MalwareAnalysis {
        product
        result_name
        result
        submitted
        analysis_started
        analysis_ended
        version
        configuration_version 
        analysis_engine_version
        analysis_definition_version
        modules
        operatingSystem {
          id
          name
          entity_type
        }
        configuration_version
        objectAssignee {
          id
          name
          entity_type
        }
      }
      ... on CaseIncident {
        name
        description
        priority
        severity
        response_types
        objectAssignee {
          name
          id
        }
        objectParticipant {
          name
          id
        }
      }
      ... on CaseRfi {
        name
        description
        priority
        severity
        information_types
        content
        objectAssignee {
          name
          id
        }
        objectParticipant {
          name
          id
        }
      }
      ... on CaseRft {
        name
        description
        priority
        severity
        takedown_types
        content
        objectAssignee {
          name
          id
        }
        objectParticipant {
          name
          id
        }
      }
      ... on Incident {
        name
        description
        objectParticipant {
          id
          name
        }
        objectAssignee {
          id
          name
        }
        incident_type
        severity
        source
        objective
        first_seen
        last_seen
      }
      ... on Indicator {
        description
        indicator_types
        pattern
        valid_from
        valid_until
        x_opencti_score
        x_opencti_detection
        indicator_types
        x_opencti_main_observable_type
        x_mitre_platforms_indicator: x_mitre_platforms
        killChainPhases {
          id
          phase_name
          kill_chain_name
          x_opencti_order
        }
      }
      ... on Infrastructure {
        name
        description
        infrastructure_types
        first_seen
        last_seen
        killChainPhases {
          id
          phase_name
          kill_chain_name
          x_opencti_order
        }
      }
      ... on ThreatActorGroup {
        name
        description
        threat_actor_types
        first_seen
        last_seen
        sophistication
        resource_level
        primary_motivation
        secondary_motivations
        goals
        roles
      }
      ... on ThreatActorIndividual {
        name
        description
        threat_actor_types
        first_seen
        last_seen
        sophistication
        resource_level
        primary_motivation
        secondary_motivations
        personal_motivations
        goals
        roles
        eye_color
        hair_color
        height {
          measure
          date_seen
        }
        weight {
          measure
          date_seen
        }
        date_of_birth
        gender
        marital_status
        job_title
        bornIn {
          name
        }
        ethnicity {
          name
        }
      }
      ... on IntrusionSet {
        name
        description
        first_seen
        last_seen
        resource_level
        primary_motivation
        secondary_motivations
        goals
      }
      ... on Malware {
        name
        description
        malware_types
        is_family
        first_seen
        last_seen
        architecture_execution_envs
        implementation_languages
        capabilities
        killChainPhases {
          id
          entity_type
          kill_chain_name
          phase_name
          x_opencti_order
        }
      }
      ... on Channel {
        name
        description
        channel_types
      }
      ... on Tool {
        name
        description
        tool_types
        tool_version
        killChainPhases {
          id
          entity_type
          kill_chain_name
          phase_name
          x_opencti_order
        }
      }
      ... on Vulnerability {
        name
        description
        modified
        x_opencti_modified_at
        x_opencti_score
        x_opencti_cisa_kev
        x_opencti_epss_score
        x_opencti_epss_percentile
        x_opencti_cwe
        x_opencti_first_seen_active
        x_opencti_cvss_base_score
        x_opencti_cvss_base_severity
        x_opencti_cvss_vector_string
        x_opencti_cvss_attack_vector
        x_opencti_cvss_attack_complexity
        x_opencti_cvss_privileges_required
        x_opencti_cvss_user_interaction
        x_opencti_cvss_scope
        x_opencti_cvss_confidentiality_impact
        x_opencti_cvss_integrity_impact
        x_opencti_cvss_availability_impact
        x_opencti_cvss_exploit_code_maturity
        x_opencti_cvss_remediation_level
        x_opencti_cvss_report_confidence
        x_opencti_cvss_temporal_score
        x_opencti_cvss_v2_base_score
        x_opencti_cvss_v2_vector_string
        x_opencti_cvss_v2_access_vector
        x_opencti_cvss_v2_access_complexity
        x_opencti_cvss_v2_authentication
        x_opencti_cvss_v2_confidentiality_impact
        x_opencti_cvss_v2_integrity_impact
        x_opencti_cvss_v2_availability_impact
        x_opencti_cvss_v2_exploitability
        x_opencti_cvss_v2_remediation_level
        x_opencti_cvss_v2_report_confidence
        x_opencti_cvss_v2_temporal_score
        x_opencti_cvss_v4_base_score
        x_opencti_cvss_v4_base_severity
        x_opencti_cvss_v4_vector_string
        x_opencti_cvss_v4_attack_vector
        x_opencti_cvss_v4_attack_complexity
        x_opencti_cvss_v4_attack_requirements
        x_opencti_cvss_v4_privileges_required
        x_opencti_cvss_v4_user_interaction
        x_opencti_cvss_v4_confidentiality_impact_v
        x_opencti_cvss_v4_confidentiality_impact_s
        x_opencti_cvss_v4_integrity_impact_v
        x_opencti_cvss_v4_integrity_impact_s
        x_opencti_cvss_v4_availability_impact_v
        x_opencti_cvss_v4_availability_impact_s
        x_opencti_cvss_v4_exploit_maturity
      }
      ... on AttackPattern {
        name
        description
        x_mitre_id
        x_mitre_permissions_required
        x_mitre_detection
        x_mitre_platforms_attack_pattern: x_mitre_platforms
        killChainPhases {
          id
          entity_type
          kill_chain_name
          phase_name
          x_opencti_order
        }
      }
      ... on Narrative {
        name
        description
      }
      ... on Sector {
        name
        description
      }
      ... on Event {
        name
        description
        event_types
      }
      ... on Organization {
        name
        description
        x_opencti_organization_type
        x_opencti_score
        contact_information
      }
      ... on SecurityPlatform {
        name
        description
        security_platform_type
      }
      ... on System {
        name
        description
        contact_information
      }
      ... on Individual {
        name
        description
        contact_information
      }
      ... on Region {
        name
        description
      }
      ... on Country {
        name
        description
      }
      ... on AdministrativeArea {
        name    
        description
      }
      ... on City {
        name
        description
      }
      ... on Position {
        name
        description
        latitude
        longitude
        street_address
        postal_code
      }
      ... on StixCyberObservable {
        observable_value
        x_opencti_description
        x_opencti_score
        created_at
        x_opencti_modified_at
        updated_at
      }
      ... on Artifact {
        x_opencti_additional_names
        x_opencti_additional_names    
        x_opencti_score
        payload_bin
        x_opencti_modified_at
        x_opencti_description
        created_at
        updated_at
        url
        hashes {
          algorithm
          hash
        }
        encryption_algorithm
        decryption_key
        mime_type
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
      }
  }
`;

interface StixCoreObjectsCustomAttributesContentProps {
  queryRef: PreloadedQuery<StixCoreObjectsCustomAttributesQuery>;
  columns: readonly WidgetColumn[];
  layout: WidgetColumnsLayout;
}

const StixCoreObjectsCustomAttributesContent = ({
  queryRef,
  columns,
  layout,
}: StixCoreObjectsCustomAttributesContentProps) => {
  const data = usePreloadedQuery(stixCoreObjectsCustomAttributesQuery, queryRef);

  if (!data?.stixCoreObject) return <WidgetNoData />;

  return (
    <WidgetCustomAttributes
      data={data.stixCoreObject}
      columns={columns}
      layout={layout}
    />
  );
};

interface StixCoreObjectsCustomAttributesProps {
  title?: string;
  variant?: string;
  height?: number;
  startDate?: string;
  endDate?: string;
  dataSelection: WidgetDataSelection[];
  widgetId: string;
  parameters?: WidgetParameters;
  popover?: React.ReactNode;
  host?: WidgetHost;
}

const StixCoreObjectsCustomAttributes = ({
  title,
  variant,
  height,
  dataSelection,
  parameters = {},
  popover,
  host,
}: StixCoreObjectsCustomAttributesProps) => {
  const { t_i18n } = useFormatter();
  const rootRef = useRef(null);
  const isPreviewMode = host?.kind === 'custom-view'
    && Boolean(host.customViewTargetEntityId)
    && host.previewMode;

  const selection = (dataSelection as WidgetDataSelection[])[0];
  const layout: WidgetColumnsLayout = (selection.layout as WidgetColumnsLayout) ?? '1';

  const resolvedEntityId = host?.kind === 'custom-view' ? host.customViewTargetEntityId : undefined;
  const entityType = host?.kind === 'custom-view' ? host.customViewTargetEntityType : undefined;

  const columns = (selection.columns && selection.columns.length > 0)
    ? selection.columns as readonly WidgetColumn[]
    : getCustomAttributesColumns(entityType);

  const queryRef = useQueryLoading<StixCoreObjectsCustomAttributesQuery>(
    stixCoreObjectsCustomAttributesQuery,
    { id: resolvedEntityId ?? '' },
  );

  return (
    <WidgetContainer
      padding="horizontal"
      height={height}
      title={parameters.title ?? title ?? t_i18n('Custom attributes')}
      variant={variant}
      action={popover}
      showPreviewTag={isPreviewMode}
    >
      <div ref={rootRef} style={{ height: '100%', overflowY: 'auto' }}>
        {!resolvedEntityId
          ? <WidgetNoHostEntity host={host} />
          : queryRef
            ? (
                <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
                  <StixCoreObjectsCustomAttributesContent
                    queryRef={queryRef}
                    columns={columns}
                    layout={layout}
                  />
                </React.Suspense>
              )
            : <Loader variant={LoaderVariant.inElement} />}
      </div>
    </WidgetContainer>
  );
};

export default StixCoreObjectsCustomAttributes;
