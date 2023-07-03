import React from 'react';
import { graphql, useFragment } from 'react-relay';
import Grid from '@mui/material/Grid';
import makeStyles from '@mui/styles/makeStyles';
import ThreatActorDetails from './ThreatActorDetails';
import ThreatActorEdition from './ThreatActorEdition';
import ThreatActorPopover from './ThreatActorPopover';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import StixCoreObjectOrStixCoreRelationshipNotes from '../../analysis/notes/StixCoreObjectOrStixCoreRelationshipNotes';
import StixDomainObjectOverview from '../../common/stix_domain_objects/StixDomainObjectOverview';
import StixCoreObjectExternalReferences from '../../analysis/external_references/StixCoreObjectExternalReferences';
import StixCoreObjectLatestHistory from '../../common/stix_core_objects/StixCoreObjectLatestHistory';
import SimpleStixObjectOrStixRelationshipStixCoreRelationships
  from '../../common/stix_core_relationships/SimpleStixObjectOrStixRelationshipStixCoreRelationships';
import { ThreatActor_threatActor$key } from './__generated__/ThreatActor_threatActor.graphql';
import StixCoreObjectOrStixRelationshipLastContainers
  from '../../common/containers/StixCoreObjectOrStixRelationshipLastContainers';

const useStyles = makeStyles(() => ({
  container: {
    margin: 0,
  },
  gridContainer: {
    marginBottom: 20,
  },
}));

const threatActorFragment = graphql`
    fragment ThreatActor_threatActor on ThreatActor {
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
            }
        }
        creators {
            id
            name
        }
        objectMarking {
            edges {
                node {
                    id
                    definition
                    definition_type
                    definition
                    x_opencti_order
                    x_opencti_color
                }
            }
        }
        objectLabel {
            edges {
                node {
                    id
                    value
                    color
                }
            }
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
        ...ThreatActorDetails_threatActor
    }
`;

const ThreatActorComponent = ({ threatActor }: { threatActor: ThreatActor_threatActor$key }) => {
  const threatActorData = useFragment(threatActorFragment, threatActor);
  const classes = useStyles();

  return (
    <div className={classes.container}>
      <StixDomainObjectHeader
        entityType={'Threat-Actor'}
        stixDomainObject={threatActorData}
        PopoverComponent={<ThreatActorPopover />}
        enableQuickSubscription
      />
      <Grid
        container={true}
        spacing={3}
        classes={{ container: classes.gridContainer }}
      >
        <Grid item={true} xs={6} style={{ paddingTop: 10 }}>
          <ThreatActorDetails threatActor={threatActorData} />
        </Grid>
        <Grid item={true} xs={6} style={{ paddingTop: 10 }}>
          <StixDomainObjectOverview stixDomainObject={threatActorData} />
        </Grid>
        <Grid item={true} xs={6} style={{ marginTop: 30 }}>
          <SimpleStixObjectOrStixRelationshipStixCoreRelationships
            stixObjectOrStixRelationshipId={threatActorData.id}
            stixObjectOrStixRelationshipLink={`/dashboard/threats/threat_actors/${threatActorData.id}/knowledge`}
          />
        </Grid>
        <Grid item={true} xs={6} style={{ marginTop: 30 }}>
          <StixCoreObjectOrStixRelationshipLastContainers
            stixCoreObjectOrStixRelationshipId={threatActorData.id}
          />
        </Grid>
        <Grid item={true} xs={6} style={{ marginTop: 30 }}>
          <StixCoreObjectExternalReferences
            stixCoreObjectId={threatActorData.id}
          />
        </Grid>
        <Grid item={true} xs={6} style={{ marginTop: 30 }}>
          <StixCoreObjectLatestHistory stixCoreObjectId={threatActorData.id} />
        </Grid>
      </Grid>
      <StixCoreObjectOrStixCoreRelationshipNotes
        stixCoreObjectOrStixCoreRelationshipId={threatActorData.id}
        defaultMarkings={(threatActorData.objectMarking?.edges ?? []).map(
          (edge) => edge.node,
        )}
      />
      <Security needs={[KNOWLEDGE_KNUPDATE]}>
        <ThreatActorEdition threatActorId={threatActorData.id} />
      </Security>
    </div>
  );
};

export default ThreatActorComponent;
