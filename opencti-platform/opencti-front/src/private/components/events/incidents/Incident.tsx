import React from 'react';
import { graphql, useFragment } from 'react-relay';
import Grid from '@mui/material/Grid';
import makeStyles from '@mui/styles/makeStyles';
import IncidentDetails from './IncidentDetails';
import IncidentEdition from './IncidentEdition';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import StixCoreObjectOrStixCoreRelationshipNotes from '../../analyses/notes/StixCoreObjectOrStixCoreRelationshipNotes';
import StixDomainObjectOverview from '../../common/stix_domain_objects/StixDomainObjectOverview';
import StixCoreObjectExternalReferences from '../../analyses/external_references/StixCoreObjectExternalReferences';
import StixCoreObjectLatestHistory from '../../common/stix_core_objects/StixCoreObjectLatestHistory';
import SimpleStixObjectOrStixRelationshipStixCoreRelationships from '../../common/stix_core_relationships/SimpleStixObjectOrStixRelationshipStixCoreRelationships';
import { Incident_incident$key } from './__generated__/Incident_incident.graphql';
import StixCoreObjectOrStixRelationshipLastContainers from '../../common/containers/StixCoreObjectOrStixRelationshipLastContainers';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  gridContainer: {
    marginBottom: 20,
  },
}));

const incidentFragment = graphql`
  fragment Incident_incident on Incident {
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
      name
    }
    objectMarking {
      id
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
    objectAssignee {
      id
      name
      entity_type
    }
    objectParticipant {
      entity_type
      id
      name
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
    ...IncidentDetails_incident
  }
`;

const Incident = ({
  incidentData,
}: {
  incidentData: Incident_incident$key;
}) => {
  const classes = useStyles();
  const incident = useFragment<Incident_incident$key>(
    incidentFragment,
    incidentData,
  );
  return (
    <>
      <Grid
        container={true}
        spacing={3}
        classes={{ container: classes.gridContainer }}
      >
        <Grid item xs={6}>
          <IncidentDetails incidentData={incident} />
        </Grid>
        <Grid item xs={6}>
          <StixDomainObjectOverview
            stixDomainObject={incident}
            displayAssignees
            displayParticipants
          />
        </Grid>
        <Grid item xs={6}>
          <SimpleStixObjectOrStixRelationshipStixCoreRelationships
            stixObjectOrStixRelationshipId={incident.id}
            stixObjectOrStixRelationshipLink={`/dashboard/events/incidents/${incident.id}/knowledge`}
          />
        </Grid>
        <Grid item xs={6}>
          <StixCoreObjectOrStixRelationshipLastContainers
            stixCoreObjectOrStixRelationshipId={incident.id}
          />
        </Grid>
        <Grid item xs={6}>
          <StixCoreObjectExternalReferences stixCoreObjectId={incident.id} />
        </Grid>
        <Grid item xs={6}>
          <StixCoreObjectLatestHistory stixCoreObjectId={incident.id} />
        </Grid>
        <Grid item xs={12}>
          <StixCoreObjectOrStixCoreRelationshipNotes
            stixCoreObjectOrStixCoreRelationshipId={incident.id}
            defaultMarkings={incident.objectMarking ?? []}
          />
        </Grid>
      </Grid>
      <Security needs={[KNOWLEDGE_KNUPDATE]}>
        <IncidentEdition incidentId={incident.id} />
      </Security>
    </>
  );
};

export default Incident;
