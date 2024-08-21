import React from 'react';
import { graphql, useFragment } from 'react-relay';
import Grid from '@mui/material/Grid';
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
import useOverviewLayoutCustomization from '../../../../utils/hooks/useOverviewLayoutCustomization';

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
  feedbackData: Feedback_case$key;
  enableReferences: boolean;
}

const Feedback: React.FC<FeedbackProps> = ({ feedbackData, enableReferences }) => {
  const feedback = useFragment(feedbackFragment, feedbackData);
  const { isFeatureEnable } = useHelper();
  const FABReplaced = isFeatureEnable('FAB_REPLACEMENT');
  const overviewLayoutCustomization = useOverviewLayoutCustomization('Feedback');
  const { canEdit } = getCurrentUserAccessRight(feedback.currentUserAccessRight);

  return (
    <>
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
                  <Grid key={key} item xs={width}>
                    <FeedbackDetails
                      feedbackData={feedback}
                    />
                  </Grid>
                );
              case 'basicInformation':
                return (
                  <Grid key={key} item xs={width}>
                    <StixDomainObjectOverview
                      stixDomainObject={feedback}
                      displayAssignees={true}
                      displayConfidence={false}
                    />
                  </Grid>
                );
              case 'relatedEntities':
                return (
                  <Grid key={key} item xs={width}>
                    <ContainerStixObjectsOrStixRelationships
                      isSupportParticipation={false}
                      container={feedback}
                      enableReferences={enableReferences}
                    />
                  </Grid>
                );
              case 'externalReferences':
                return (
                  <Grid key={key} item xs={width}>
                    <StixCoreObjectExternalReferences
                      stixCoreObjectId={feedback.id}
                    />
                  </Grid>
                );
              case 'mostRecentHistory':
                return (
                  <Grid key={key} item xs={width}>
                    <StixCoreObjectLatestHistory
                      stixCoreObjectId={feedback.id}
                    />
                  </Grid>
                );
              default:
                return null;
            }
          })
        }
      </Grid>
      {!FABReplaced
        && <Security needs={[KNOWLEDGE_KNUPDATE]} hasAccess={canEdit}>
          <FeedbackEdition feedbackId={feedback.id} />
        </Security>
      }
    </>
  );
};

export default Feedback;
