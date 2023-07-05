import Grid from '@mui/material/Grid';
import makeStyles from '@mui/styles/makeStyles';
import React from 'react';
import { graphql, useFragment } from 'react-relay';
import StixCoreObjectOrStixCoreRelationshipNotes from '../../analysis/notes/StixCoreObjectOrStixCoreRelationshipNotes';
import ContainerHeader from '../../common/containers/ContainerHeader';
import StixCoreObjectLatestHistory from '../../common/stix_core_objects/StixCoreObjectLatestHistory';
import StixDomainObjectOverview from '../../common/stix_domain_objects/StixDomainObjectOverview';
import TaskDetails from './TaskDetails';
import TaskPopover from './TaskPopover';
import { Tasks_tasks$key } from './__generated__/Tasks_tasks.graphql';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import Security from '../../../../utils/Security';
import TaskEdition from './TaskEdition';
import ContainerStixObjectsOrStixRelationships from '../../common/containers/ContainerStixObjectsOrStixRelationships';

const useStyles = makeStyles(() => ({
  gridContainer: {
    marginBottom: 20,
  },
  container: {
    margin: 0,
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
      }
    }
    objectMarking {
      edges {
        node {
          definition
          definition_type
          id
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
          entity_type
          id
          name
        }
      }
    }
    objectParticipant {
      edges {
        node {
          entity_type
          id
          name
        }
      }
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

const TaskComponent = ({ data }: { data: Tasks_tasks$key }) => {
  const classes = useStyles();
  const task = useFragment(taskFragment, data);

  return (
    <div className={classes.container}>
      <ContainerHeader
        container={task}
        PopoverComponent={<TaskPopover id={task.id} />}
        enableSuggestions={false}
      />
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
          />
        </Grid>
        <Grid item={true} xs={6} style={{ marginTop: 30 }}>
          <StixCoreObjectLatestHistory stixCoreObjectId={task.id} />
        </Grid>
      </Grid>
      <StixCoreObjectOrStixCoreRelationshipNotes
        stixCoreObjectOrStixCoreRelationshipId={task.id}
        defaultMarkings={(task.objectMarking?.edges ?? []).map(
          (edge) => edge.node,
        )}
      />
      <Security needs={[KNOWLEDGE_KNUPDATE]}>
        <TaskEdition caseId={task.id} />
      </Security>
    </div>
  );
};

export default TaskComponent;
