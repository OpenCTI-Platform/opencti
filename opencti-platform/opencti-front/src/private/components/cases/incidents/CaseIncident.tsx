import React, { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
import Grid from '@mui/material/Grid';
import makeStyles from '@mui/styles/makeStyles';
import CaseIncidentDetails from './CaseIncidentDetails';
import CaseIncidentPopover from './CaseIncidentPopover';
import ContainerHeader from '../../common/containers/ContainerHeader';
import StixDomainObjectOverview from '../../common/stix_domain_objects/StixDomainObjectOverview';
import Security from '../../../../utils/Security';
import { SETTINGS } from '../../../../utils/hooks/useGranted';
import CaseIncidentEdition from './CaseIncidentEdition';
import StixCoreObjectExternalReferences from '../../analysis/external_references/StixCoreObjectExternalReferences';
import StixCoreObjectLatestHistory from '../../common/stix_core_objects/StixCoreObjectLatestHistory';
import StixCoreObjectOrStixCoreRelationshipNotes from '../../analysis/notes/StixCoreObjectOrStixCoreRelationshipNotes';
import ContainerStixObjectsOrStixRelationships from '../../common/containers/ContainerStixObjectsOrStixRelationships';
import { CaseIncident_case$key } from './__generated__/CaseIncident_case.graphql';

const useStyles = makeStyles(() => ({
  gridContainer: {
    marginBottom: 20,
  },
  container: {
    margin: 0,
  },
}));

const caseIncidentFragment = graphql`
  fragment CaseIncident_case on CaseIncident {
    id
    name
    standard_id
    entity_type
    x_opencti_stix_ids
    created
    modified
    created_at
    revoked
    description
    confidence
    createdBy {
      ... on Identity {
        id
        name
        entity_type
      }
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
    ...CaseIncidentDetails_case
    ...ContainerHeader_container
    ...ContainerStixObjectsOrStixRelationships_container
  }
`;

interface CaseIncidentProps {
  data: CaseIncident_case$key;
}

const CaseIncidentComponent: FunctionComponent<CaseIncidentProps> = ({ data }) => {
  const classes = useStyles();
  const caseIncidentData = useFragment(caseIncidentFragment, data);

  return (
    <div className={classes.container}>
      <ContainerHeader
        container={caseIncidentData}
        PopoverComponent={<CaseIncidentPopover id={caseIncidentData.id} />}
        enableSuggestions={false}
        disableSharing={true}
      />
      <Grid
        container={true}
        spacing={3}
        classes={{ container: classes.gridContainer }}
      >
        <Grid item={true} xs={6} style={{ paddingTop: 10 }}>
          <CaseIncidentDetails caseIncidentData={caseIncidentData} />
        </Grid>
        <Grid item={true} xs={6} style={{ paddingTop: 10 }}>
          <StixDomainObjectOverview
            stixDomainObject={caseIncidentData}
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
        <Grid item={true} xs={12} style={{ paddingTop: 24 }}>
          <ContainerStixObjectsOrStixRelationships
            isSupportParticipation={true}
            container={caseIncidentData}
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
          <StixCoreObjectExternalReferences stixCoreObjectId={caseIncidentData.id} />
        </Grid>
        <Grid item={true} xs={6}>
          <StixCoreObjectLatestHistory stixCoreObjectId={caseIncidentData.id} />
        </Grid>
      </Grid>
      <StixCoreObjectOrStixCoreRelationshipNotes
        stixCoreObjectOrStixCoreRelationshipId={caseIncidentData.id}
        defaultMarking={(caseIncidentData.objectMarking?.edges ?? []).map(
          (edge) => edge.node,
        )}
      />
      <Security needs={[SETTINGS]}>
        <CaseIncidentEdition caseId={caseIncidentData.id} />
      </Security>
    </div>
  );
};

export default CaseIncidentComponent;
