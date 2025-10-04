import React from 'react';
import { graphql, useFragment } from 'react-relay';
import { ThreatActorGroup_ThreatActorGroup$key } from '@private/components/threats/threat_actors_group/__generated__/ThreatActorGroup_ThreatActorGroup.graphql';
import ThreatActorGroupDetails from './ThreatActorGroupDetails';
import StixCoreObjectOrStixCoreRelationshipNotes from '../../analyses/notes/StixCoreObjectOrStixCoreRelationshipNotes';
import StixDomainObjectOverview from '../../common/stix_domain_objects/StixDomainObjectOverview';
import StixCoreObjectExternalReferences from '../../analyses/external_references/StixCoreObjectExternalReferences';
import StixCoreObjectLatestHistory from '../../common/stix_core_objects/StixCoreObjectLatestHistory';
import SimpleStixObjectOrStixRelationshipStixCoreRelationships from '../../common/stix_core_relationships/SimpleStixObjectOrStixRelationshipStixCoreRelationships';
import StixCoreObjectOrStixRelationshipLastContainers from '../../common/containers/StixCoreObjectOrStixRelationshipLastContainers';
import useOverviewLayoutCustomization from '../../../../utils/hooks/useOverviewLayoutCustomization';
import { Grid } from '@components';

const threatActorGroupFragment = graphql`
  fragment ThreatActorGroup_ThreatActorGroup on ThreatActorGroup {
    id
    standard_id
    entity_type
    x_opencti_stix_ids
    spec_version
    revoked
    confidence
    created
    modified
    created_at
    updated_at
    createdBy {
      ... on Identity {
        id
        name
        entity_type
        x_opencti_reliability
      }
    }
    creators {
      id
      name
    }
    objectMarking {
      id
      definition
      definition_type
      definition
      x_opencti_order
      x_opencti_color
    }
    objectLabel {
      id
      value
      color
    }
    name
    aliases
    status {
      id
      order
      template {
        name
        color
      }
    }
    workflowEnabled
    ...ThreatActorGroupDetails_ThreatActorGroup
  }
`;

interface ThreatActorGroupProps {
  threatActorGroupData: ThreatActorGroup_ThreatActorGroup$key
}

const ThreatActorGroup: React.FC<ThreatActorGroupProps> = ({ threatActorGroupData }) => {
  const threatActorGroup = useFragment<ThreatActorGroup_ThreatActorGroup$key>(
    threatActorGroupFragment,
    threatActorGroupData,
  );
  const overviewLayoutCustomization = useOverviewLayoutCustomization(threatActorGroup.entity_type);

  return (
    <div data-testid="threat-actor-group-details-page">
      <Grid
        container={true}
        spacing={3}
        style={{ marginBottom: 20 }}
      >
        {
          overviewLayoutCustomization.map(({ key, width }) => {
            switch (key) {
              case 'details':
                return (
                  <Grid key={key} size={width}>
                    <ThreatActorGroupDetails threatActorGroup={threatActorGroup} />
                  </Grid>
                );
              case 'basicInformation':
                return (
                  <Grid key={key} size={width}>
                    <StixDomainObjectOverview stixDomainObject={threatActorGroup} />
                  </Grid>
                );
              case 'latestCreatedRelationships':
                return (
                  <Grid key={key} size={width}>
                    <SimpleStixObjectOrStixRelationshipStixCoreRelationships
                      stixObjectOrStixRelationshipId={threatActorGroup.id}
                      stixObjectOrStixRelationshipLink={`/dashboard/threats/threat_actors_group/${threatActorGroup.id}/knowledge`}
                    />
                  </Grid>
                );
              case 'latestContainers':
                return (
                  <Grid key={key} size={width}>
                    <StixCoreObjectOrStixRelationshipLastContainers
                      stixCoreObjectOrStixRelationshipId={threatActorGroup.id}
                    />
                  </Grid>
                );
              case 'externalReferences':
                return (
                  <Grid key={key} size={width}>
                    <StixCoreObjectExternalReferences
                      stixCoreObjectId={threatActorGroup.id}
                    />
                  </Grid>
                );
              case 'mostRecentHistory':
                return (
                  <Grid key={key} size={width}>
                    <StixCoreObjectLatestHistory
                      stixCoreObjectId={threatActorGroup.id}
                    />
                  </Grid>
                );
              case 'notes':
                return (
                  <Grid key={key} size={width}>
                    <StixCoreObjectOrStixCoreRelationshipNotes
                      stixCoreObjectOrStixCoreRelationshipId={threatActorGroup.id}
                      defaultMarkings={threatActorGroup.objectMarking ?? []}
                    />
                  </Grid>
                );
              default:
                return null;
            }
          })
        }
      </Grid>
    </div>
  );
};

export default ThreatActorGroup;
