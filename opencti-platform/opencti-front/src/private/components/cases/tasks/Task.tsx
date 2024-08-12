import Grid from '@mui/material/Grid';
import makeStyles from '@mui/styles/makeStyles';
import React from 'react';
import { graphql, useFragment } from 'react-relay';
import useHelper from 'src/utils/hooks/useHelper';
import StixCoreObjectOrStixCoreRelationshipNotes from '../../analyses/notes/StixCoreObjectOrStixCoreRelationshipNotes';
import StixCoreObjectLatestHistory from '../../common/stix_core_objects/StixCoreObjectLatestHistory';
import StixDomainObjectOverview from '../../common/stix_domain_objects/StixDomainObjectOverview';
import TaskDetails from './TaskDetails';
import { Tasks_tasks$key } from './__generated__/Tasks_tasks.graphql';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import Security from '../../../../utils/Security';
import TaskEdition from './TaskEdition';
import ContainerStixObjectsOrStixRelationships from '../../common/containers/ContainerStixObjectsOrStixRelationships';
import useOverviewLayoutCustomization from '../../../../utils/hooks/useOverviewLayoutCustomization';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  gridContainer: {
    marginBottom: 20,
  },
}));

export const taskFragment = graphql`
  fragment Tasks_tasks on Task {
    id
    standard_id
    name
    due_date
    description
    workflowEnabled
    revoked
    created_at
    updated_at
    created
    modified
    creators {
      id
      name
    }
    createdBy {
      ... on Identity {
        id
        name
        entity_type
        x_opencti_reliability
      }
    }
    objectMarking {
      id
      definition
      definition_type
      x_opencti_color
    }
    objectLabel {
      id
      value
      color
    }
    objectAssignee {
      entity_type
      id
      name
    }
    objectParticipant {
      entity_type
      id
      name
    }
    status {
      template {
        name
        color
      }
    }
    ...TaskDetails_task
    ...ContainerHeader_container
    ...ContainerStixObjectsOrStixRelationships_container
  }
`;

const TaskComponent = ({ data, enableReferences }: { data: Tasks_tasks$key, enableReferences: boolean }) => {
  const classes = useStyles();
  const task = useFragment(taskFragment, data);
  const { isFeatureEnable } = useHelper();
  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');
  const overviewLayoutCustomization = useOverviewLayoutCustomization('Task');
  return (
    <>
      <Grid
        container={true}
        spacing={3}
        classes={{ container: classes.gridContainer }}
      >
        {
          overviewLayoutCustomization.map(({ key, width }) => {
            switch (key) {
              case 'details':
                return (
                  <Grid key={key} item xs={width}>
                    <TaskDetails
                      tasksData={task}
                    />
                  </Grid>
                );
              case 'basicInformation':
                return (
                  <Grid key={key} item xs={width}>
                    <StixDomainObjectOverview
                      stixDomainObject={task}
                      displayAssignees
                      displayParticipants
                    />
                  </Grid>
                );
              case 'relatedEntities':
                return (
                  <Grid key={key} item xs={width}>
                    <ContainerStixObjectsOrStixRelationships
                      isSupportParticipation={false}
                      container={task}
                      enableReferences={enableReferences}
                    />
                  </Grid>
                );
              case 'mostRecentHistory':
                return (
                  <Grid key={key} item xs={width}>
                    <StixCoreObjectLatestHistory
                      stixCoreObjectId={task.id}
                    />
                  </Grid>
                );
              case 'notes':
                return (
                  <Grid key={key} item xs={width}>
                    <StixCoreObjectOrStixCoreRelationshipNotes
                      stixCoreObjectOrStixCoreRelationshipId={task.id}
                      defaultMarkings={task.objectMarking ?? []}
                    />
                  </Grid>
                );
              default:
                return null;
            }
          })
        }
      </Grid>
      {!isFABReplaced && (
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <TaskEdition caseId={task.id} />
        </Security>
      )}
    </>
  );
};

export default TaskComponent;
