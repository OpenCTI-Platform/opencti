import React, { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
import Grid from '@mui/material/Grid';
import makeStyles from '@mui/styles/makeStyles';
import IncidentDetails from './IncidentDetails';
import { Incident_case$key } from './__generated__/Incident_case.graphql';
import IncidentPopover from './IncidentPopover';
import ContainerHeader from '../../common/containers/ContainerHeader';
import StixDomainObjectOverview from '../../common/stix_domain_objects/StixDomainObjectOverview';
import Security from '../../../../utils/Security';
import { SETTINGS } from '../../../../utils/hooks/useGranted';
import IncidentEdition from './IncidentEdition';
import StixCoreObjectExternalReferences from '../../analysis/external_references/StixCoreObjectExternalReferences';
import StixCoreObjectLatestHistory from '../../common/stix_core_objects/StixCoreObjectLatestHistory';
import StixCoreObjectOrStixCoreRelationshipNotes from '../../analysis/notes/StixCoreObjectOrStixCoreRelationshipNotes';

const useStyles = makeStyles(() => ({
  gridContainer: {
    marginBottom: 20,
  },
  container: {
    margin: 0,
  },
}));

const incidentFragment = graphql`
  fragment Incident_case on Case {
    id
    name
    standard_id
    x_opencti_stix_ids
    created
    modified
    created_at
    rating
    revoked
    description
    createdBy {
      ... on Identity {
        id
        name
        entity_type
      }
    }
    creator {
      id
      name
    }
    objectMarking {
      edges {
        node {
          id
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
    objectAssignee {
      edges {
        node {
          id
          name
          entity_type
        }
      }
    }
    x_opencti_stix_ids
    status {
      id
      order
      template {
        name
        color
      }
    }
    workflowEnabled
    ...IncidentDetails_case
    ...ContainerHeader_container
    ...ContainerStixObjectsOrStixRelationships_container
  }
`;

interface IncidentProps {
  data: Incident_case$key;
}

const IncidentComponent: FunctionComponent<IncidentProps> = ({ data }) => {
  const classes = useStyles();
  const caseData = useFragment(incidentFragment, data);

  return (
    <div className={classes.container}>
      <ContainerHeader
        container={caseData}
        PopoverComponent={<IncidentPopover id={caseData.id} />}
        enableSuggestions={false}
        disableSharing={true}
      />
      <Grid
        container={true}
        spacing={3}
        classes={{ container: classes.gridContainer }}
      >
        <Grid item={true} xs={6} style={{ paddingTop: 10 }}>
          <IncidentDetails caseData={caseData} />
        </Grid>
        <Grid item={true} xs={6} style={{ paddingTop: 10 }}>
          <StixDomainObjectOverview
            stixDomainObject={caseData}
            displayAssignees={true}
          />
        </Grid>
      </Grid>
      <Grid
        container={true}
        spacing={3}
        classes={{ container: classes.gridContainer }}
        style={{ marginTop: 25 }}
      >
        <Grid item={true} xs={6}>
          <StixCoreObjectExternalReferences stixCoreObjectId={caseData.id} />
        </Grid>
        <Grid item={true} xs={6}>
          <StixCoreObjectLatestHistory stixCoreObjectId={caseData.id} />
        </Grid>
      </Grid>
      <StixCoreObjectOrStixCoreRelationshipNotes
        stixCoreObjectOrStixCoreRelationshipId={caseData.id}
        defaultMarking={(caseData.objectMarking?.edges ?? []).map(
          (edge) => edge.node,
        )}
      />
      <Security needs={[SETTINGS]}>
        <IncidentEdition caseId={caseData.id} />
      </Security>
    </div>
  );
};

export default IncidentComponent;
