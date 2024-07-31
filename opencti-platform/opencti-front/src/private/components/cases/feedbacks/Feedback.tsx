import React, { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
import Grid from '@mui/material/Grid';
import makeStyles from '@mui/styles/makeStyles';
import useHelper from 'src/utils/hooks/useHelper';
import FeedbackDetails from './FeedbackDetails';
import StixDomainObjectOverview from '../../common/stix_domain_objects/StixDomainObjectOverview';
import ContainerStixObjectsOrStixRelationships from '../../common/containers/ContainerStixObjectsOrStixRelationships';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import FeedbackEdition from './FeedbackEdition';
import StixCoreObjectExternalReferences from '../../analyses/external_references/StixCoreObjectExternalReferences';
import StixCoreObjectLatestHistory from '../../common/stix_core_objects/StixCoreObjectLatestHistory';
import { Feedback_case$key } from './__generated__/Feedback_case.graphql';
import { getCurrentUserAccessRight } from '../../../../utils/authorizedMembers';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  gridContainer: {
    marginBottom: 20,
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
    currentUserAccessRight
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
  enableReferences: boolean;
}

const FeedbackComponent: FunctionComponent<FeedbackProps> = ({ data, enableReferences }) => {
  const classes = useStyles();
  const feedbackData = useFragment(feedbackFragment, data);
  const { isFeatureEnable } = useHelper();
  const FABReplaced = isFeatureEnable('FAB_REPLACEMENT');

  const { canEdit } = getCurrentUserAccessRight(feedbackData);

  return (
    <>
      <Grid
        container={true}
        spacing={3}
        classes={{ container: classes.gridContainer }}
      >
        <Grid item xs={6}>
          <FeedbackDetails feedbackData={feedbackData} />
        </Grid>
        <Grid item xs={6}>
          <StixDomainObjectOverview
            stixDomainObject={feedbackData}
            displayAssignees={true}
            displayConfidence={false}
          />
        </Grid>
        <Grid item xs={12}>
          <ContainerStixObjectsOrStixRelationships
            isSupportParticipation={false}
            container={feedbackData}
            enableReferences={enableReferences}
          />
        </Grid>
        <Grid item xs={6}>
          <StixCoreObjectExternalReferences
            stixCoreObjectId={feedbackData.id}
          />
        </Grid>
        <Grid item xs={6}>
          <StixCoreObjectLatestHistory stixCoreObjectId={feedbackData.id} />
        </Grid>
      </Grid>
      {!FABReplaced
        && <Security needs={[KNOWLEDGE_KNUPDATE]} hasAccess={canEdit}>
          <FeedbackEdition feedbackId={feedbackData.id} />
        </Security>
      }
    </>
  );
};

export default FeedbackComponent;
