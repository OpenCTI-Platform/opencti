import Grid from '@mui/material/Grid';
import makeStyles from '@mui/styles/makeStyles';
import React from 'react';
import { graphql, useFragment } from 'react-relay';
import StixCoreObjectOrStixCoreRelationshipNotes from '../../analyses/notes/StixCoreObjectOrStixCoreRelationshipNotes';
import StixCoreObjectLatestHistory from '../../common/stix_core_objects/StixCoreObjectLatestHistory';
import StixDomainObjectOverview from '../../common/stix_domain_objects/StixDomainObjectOverview';
import TaskDetails from './TaskDetails';
import { Tasks_tasks$key } from './__generated__/Tasks_tasks.graphql';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import Security from '../../../../utils/Security';
import TaskEdition from './TaskEdition';
import ContainerStixObjectsOrStixRelationships from '../../common/containers/ContainerStixObjectsOrStixRelationships';

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
  return (
    <>
      <Grid
        container={true}
        spacing={3}
        classes={{ container: classes.gridContainer }}
      >
        <Grid item={true} xs={6} style={{ paddingTop: 10 }}>
          <TaskDetails tasksData={task} />
        </Grid>
        <Grid item={true} xs={6} style={{ paddingTop: 10 }}>
          <StixDomainObjectOverview
            stixDomainObject={task}
            displayAssignees
            displayParticipants
          />
        </Grid>
        <Grid item={true} xs={6} style={{ marginTop: 30 }}>
          <ContainerStixObjectsOrStixRelationships
            isSupportParticipation={false}
            container={task}
            enableReferences={enableReferences}
          />
        </Grid>
        <Grid item={true} xs={6} style={{ marginTop: 30 }}>
          <StixCoreObjectLatestHistory stixCoreObjectId={task.id} />
        </Grid>
      </Grid>
      <StixCoreObjectOrStixCoreRelationshipNotes
        stixCoreObjectOrStixCoreRelationshipId={task.id}
        defaultMarkings={task.objectMarking ?? []}
      />
      <Security needs={[KNOWLEDGE_KNUPDATE]}>
        <TaskEdition caseId={task.id} />
      </Security>
    </>
  );
};

export default TaskComponent;
