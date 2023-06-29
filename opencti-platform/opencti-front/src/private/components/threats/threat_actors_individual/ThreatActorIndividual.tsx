import React from 'react';
import { graphql, useFragment } from 'react-relay';
import Grid from '@mui/material/Grid';
import makeStyles from '@mui/styles/makeStyles';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import StixCoreObjectOrStixCoreRelationshipNotes from '../../analysis/notes/StixCoreObjectOrStixCoreRelationshipNotes';
import StixDomainObjectOverview from '../../common/stix_domain_objects/StixDomainObjectOverview';
import StixCoreObjectExternalReferences from '../../analysis/external_references/StixCoreObjectExternalReferences';
import StixCoreObjectLatestHistory from '../../common/stix_core_objects/StixCoreObjectLatestHistory';
import SimpleStixObjectOrStixRelationshipStixCoreRelationships from '../../common/stix_core_relationships/SimpleStixObjectOrStixRelationshipStixCoreRelationships';
import StixCoreObjectOrStixRelationshipLastContainers from '../../common/containers/StixCoreObjectOrStixRelationshipLastContainers';
import ThreatActorIndividualDetails from './ThreatActorIndividualDetails';
import ThreatActorIndividualPopover from './ThreatActorIndividualPopover';
import ThreatActorIndividualEdition from './ThreatActorIndividualEdition';
import {
  ThreatActorIndividual_ThreatActorIndividual$key,
} from './__generated__/ThreatActorIndividual_ThreatActorIndividual.graphql';

const useStyles = makeStyles(() => ({
  gridContainer: {
    marginBottom: 20,
  },
  container: {
    margin: 0,
  },
}));

export const threatActorIndividualFragment = graphql`
  fragment ThreatActorIndividual_ThreatActorIndividual on ThreatActorIndividual {
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
    ...ThreatActorIndividualDetails_ThreatActorIndividual
    }
  `;

const ThreatActorIndividualComponent = ({ data }: { data: ThreatActorIndividual_ThreatActorIndividual$key }) => {
  const classes = useStyles();
  const threatActorIndividual = useFragment<ThreatActorIndividual_ThreatActorIndividual$key>(threatActorIndividualFragment, data);

  return (
    <div className={classes.container}>
      <StixDomainObjectHeader
        entityType={'Threat-Actor-Individual'}
        stixDomainObject={threatActorIndividual}
        PopoverComponent={ThreatActorIndividualPopover}
      />
      <Grid
        container={true}
        spacing={3}
        classes={{ container: classes.gridContainer }}
      >
        <Grid item={true} xs={6} style={{ paddingTop: 10 }}>
          <ThreatActorIndividualDetails threatActorIndividualData={threatActorIndividual} />
        </Grid>
        <Grid item={true} xs={6} style={{ paddingTop: 10 }}>
          <StixDomainObjectOverview stixDomainObject={threatActorIndividual} />
        </Grid>
        <Grid item={true} xs={6} style={{ marginTop: 30 }}>
          <SimpleStixObjectOrStixRelationshipStixCoreRelationships
            stixObjectOrStixRelationshipId={threatActorIndividual.id}
            stixObjectOrStixRelationshipLink={`/dashboard/threats/threat_actors_individual/${threatActorIndividual.id}/knowledge`}
          />
        </Grid>
        <Grid item={true} xs={6} style={{ marginTop: 30 }}>
          <StixCoreObjectOrStixRelationshipLastContainers
            stixCoreObjectOrStixRelationshipId={threatActorIndividual.id}
          />
        </Grid>
        <Grid item={true} xs={6} style={{ marginTop: 30 }}>
          <StixCoreObjectExternalReferences
            stixCoreObjectId={threatActorIndividual.id}
          />
        </Grid>
        <Grid item={true} xs={6} style={{ marginTop: 30 }}>
          <StixCoreObjectLatestHistory stixCoreObjectId={threatActorIndividual.id} />
        </Grid>
      </Grid>
      <StixCoreObjectOrStixCoreRelationshipNotes
        stixCoreObjectOrStixCoreRelationshipId={threatActorIndividual.id}
        defaultMarkings={(threatActorIndividual.objectMarking?.edges ?? []).map(
          (edge) => edge.node,
        )}
      />
      <Security needs={[KNOWLEDGE_KNUPDATE]}>
        <ThreatActorIndividualEdition threatActorIndividualId={threatActorIndividual.id} />
      </Security>
    </div>
  );
};

export default ThreatActorIndividualComponent;
