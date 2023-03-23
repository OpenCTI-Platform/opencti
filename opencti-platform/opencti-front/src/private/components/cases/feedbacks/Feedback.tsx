import React, { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
import Grid from '@mui/material/Grid';
import makeStyles from '@mui/styles/makeStyles';
import FeedbackDetails from './FeedbackDetails';
import FeedbackPopover from './FeedbackPopover';
import ContainerHeader from '../../common/containers/ContainerHeader';
import StixDomainObjectOverview from '../../common/stix_domain_objects/StixDomainObjectOverview';
import ContainerStixObjectsOrStixRelationships from '../../common/containers/ContainerStixObjectsOrStixRelationships';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import FeedbackEdition from './FeedbackEdition';
import StixCoreObjectExternalReferences from '../../analysis/external_references/StixCoreObjectExternalReferences';
import StixCoreObjectLatestHistory from '../../common/stix_core_objects/StixCoreObjectLatestHistory';
import { Feedback_case$key } from './__generated__/Feedback_case.graphql';

const useStyles = makeStyles(() => ({
  gridContainer: {
    marginBottom: 20,
  },
  container: {
    margin: 0,
  },
}));

const feedbackFragment = graphql`
  fragment Feedback_case on Feedback {
    id
    name
    standard_id
    entity_type
    x_opencti_stix_ids
    created
    modified
    created_at
    rating
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
    creators {
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
  const feedbackData = useFragment(feedbackFragment, data);

  return (
    <div className={classes.container}>
      <ContainerHeader
        container={feedbackData}
        PopoverComponent={<FeedbackPopover id={feedbackData.id} />}
        enableSuggestions={false}
        disableSharing={true}
      />
      <Grid
        container={true}
        spacing={3}
        classes={{ container: classes.gridContainer }}
      >
        <Grid item={true} xs={6} style={{ paddingTop: 10 }}>
          <FeedbackDetails feedbackData={feedbackData} />
        </Grid>
        <Grid item={true} xs={6} style={{ paddingTop: 10 }}>
          <StixDomainObjectOverview
            stixDomainObject={feedbackData}
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
            isSupportParticipation={false}
            container={feedbackData}
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
          <StixCoreObjectExternalReferences stixCoreObjectId={feedbackData.id} />
        </Grid>
        <Grid item={true} xs={6}>
          <StixCoreObjectLatestHistory stixCoreObjectId={feedbackData.id} />
        </Grid>
      </Grid>
      <Security needs={[KNOWLEDGE_KNUPDATE]}>
        <FeedbackEdition feedbackId={feedbackData.id} />
      </Security>
    </div>
  );
};

export default FeedbackComponent;
