import React, { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
import Grid from '@mui/material/Grid';
import makeStyles from '@mui/styles/makeStyles';
import FeedbackDetails from './FeedbackDetails';
import { Feedback_case$key } from './__generated__/Feedback_case.graphql';
import FeedbackPopover from './FeedbackPopover';
import ContainerHeader from '../../common/containers/ContainerHeader';
import StixDomainObjectOverview from '../../common/stix_domain_objects/StixDomainObjectOverview';
import ContainerStixObjectsOrStixRelationships from '../../common/containers/ContainerStixObjectsOrStixRelationships';
import Security from '../../../../utils/Security';
import { SETTINGS } from '../../../../utils/hooks/useGranted';
import FeedbackEdition from './FeedbackEdition';
import StixCoreObjectExternalReferences from '../../analysis/external_references/StixCoreObjectExternalReferences';
import StixCoreObjectLatestHistory from '../../common/stix_core_objects/StixCoreObjectLatestHistory';

const useStyles = makeStyles(() => ({
  gridContainer: {
    marginBottom: 20,
  },
  container: {
    margin: 0,
  },
}));

const feedbackFragment = graphql`
  fragment Feedback_case on Case {
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
          definition
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
    ...FeedbackDetails_case
    ...ContainerHeader_container
    ...ContainerStixObjectsOrStixRelationships_container
  }
`;

interface FeedbackProps {
  data: Feedback_case$key;
}

const FeedbackComponent: FunctionComponent<FeedbackProps> = ({ data }) => {
  const classes = useStyles();
  const caseData = useFragment(feedbackFragment, data);

  return (
    <div className={classes.container}>
      <ContainerHeader
        container={caseData}
        PopoverComponent={<FeedbackPopover id={caseData.id} />}
        enableSuggestions={false}
        disableSharing={true}
      />
      <Grid
        container={true}
        spacing={3}
        classes={{ container: classes.gridContainer }}
      >
        <Grid item={true} xs={6} style={{ paddingTop: 10 }}>
          <FeedbackDetails caseData={caseData} />
        </Grid>
        <Grid item={true} xs={6} style={{ paddingTop: 10 }}>
          <StixDomainObjectOverview stixDomainObject={caseData} />
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
            isSupportParticipation={false}
            container={caseData}
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
      <Security needs={[SETTINGS]}>
        <FeedbackEdition caseId={caseData.id} />
      </Security>
    </div>
  );
};

export default FeedbackComponent;
