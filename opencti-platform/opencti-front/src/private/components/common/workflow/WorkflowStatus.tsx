import React, { FunctionComponent, useState } from 'react';
import { graphql, useFragment, useMutation } from 'react-relay';
import { Menu, MenuItem } from '@mui/material';
import { ArrowDropDownOutlined } from '@mui/icons-material';
import ItemStatus from '../../../../components/ItemStatus';
import Button from '../../../../components/common/button/Button';
import { WorkflowStatus_data$key } from './__generated__/WorkflowStatus_data.graphql';
import { WorkflowStatusTriggerMutation } from './__generated__/WorkflowStatusTriggerMutation.graphql';
import { useFormatter } from '../../../../components/i18n';

export const workflowStatusFragment = graphql`
  fragment WorkflowStatus_data on DraftWorkspace {
    id
    workflowInstance {
      id
      currentState
      currentStatus {
        id
        template {
          name
          color
        }
      }
      allowedTransitions {
        event
        toState
        toStatus {
          id
          template {
            name
            color
          }
        }
      }
    }
  }
`;

const workflowStatusTriggerMutation = graphql`
  mutation WorkflowStatusTriggerMutation($entityId: String!, $eventName: String!) {
    triggerWorkflowEvent(entityId: $entityId, eventName: $eventName) {
      success
      reason
      newState
      instance {
        id
        currentState
        currentStatus {
          id
          template {
            name
            color
          }
        }
        allowedTransitions {
          event
          toState
          toStatus {
            id
            template {
              name
              color
            }
          }
        }
      }
    }
  }
`;

interface WorkflowStatusProps {
  data: WorkflowStatus_data$key;
}

interface WorkflowTransitionsProps extends WorkflowStatusProps {
  refetch: () => void;
}

const WorkflowStatus: FunctionComponent<WorkflowStatusProps> = ({ data }) => {
  const draft = useFragment(workflowStatusFragment, data);

  if (!draft.workflowInstance) {
    return null;
  }

  const { workflowInstance } = draft;
  const currentStatus = workflowInstance.currentStatus;

  return (
    <ItemStatus status={currentStatus} />
  );
};

export const WorkflowTransitions: FunctionComponent<WorkflowTransitionsProps> = ({ data, refetch }) => {
  const { t_i18n } = useFormatter();
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);

  const draft = useFragment(workflowStatusFragment, data);
  const [commit] = useMutation<WorkflowStatusTriggerMutation>(workflowStatusTriggerMutation);

  if (!draft.workflowInstance || draft.workflowInstance.allowedTransitions.length === 0) {
    return null;
  }

  const { workflowInstance } = draft;

  const handleOpen = (event: React.MouseEvent<HTMLButtonElement>) => {
    setAnchorEl(event.currentTarget);
  };

  const handleClose = () => {
    setAnchorEl(null);
  };

  const handleTransition = (eventName: string) => {
    commit({
      variables: {
        entityId: draft.id,
        eventName,
      },
      onCompleted: () => {
        handleClose();
        refetch();
      },
    });
  };

  return (
    <>
      <Button
        variant="secondary"
        size="small"
        onClick={handleOpen}
        endIcon={<ArrowDropDownOutlined />}
      >
        {t_i18n('Workflow')}
      </Button>
      <Menu anchorEl={anchorEl} open={Boolean(anchorEl)} onClose={handleClose}>
        {workflowInstance.allowedTransitions.map((transition) => (
          <MenuItem
            key={transition.event}
            onClick={() => handleTransition(transition.event)}
          >
            {transition.event}
          </MenuItem>
        ))}
      </Menu>
    </>
  );
};

export default WorkflowStatus;
