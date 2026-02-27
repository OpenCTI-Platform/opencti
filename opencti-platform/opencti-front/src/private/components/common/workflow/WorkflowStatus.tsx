import React, { FunctionComponent, useState } from 'react';
import { graphql, useFragment, useMutation } from 'react-relay';
import { Alert, AlertTitle, Dialog, DialogActions, DialogContent, DialogContentText, DialogTitle, Menu, MenuItem } from '@mui/material';
import { ArrowDropDownOutlined } from '@mui/icons-material';
import ItemStatus from '../../../../components/ItemStatus';
import Button from '../../../../components/common/button/Button';
import { WorkflowStatus_data$key } from './__generated__/WorkflowStatus_data.graphql';
import { WorkflowStatusTriggerMutation } from './__generated__/WorkflowStatusTriggerMutation.graphql';
import { useFormatter } from '../../../../components/i18n';
import useSwitchDraft from '../../drafts/useSwitchDraft';
import { MESSAGING$ } from '../../../../relay/environment';
import { useNavigate } from 'react-router-dom';

export const workflowStatusFragment = graphql`
  fragment WorkflowStatus_data on DraftWorkspace {
    id
    entity_id
    processingCount
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
        actions
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
          actions
          toStatus {
            id
            template {
              name
              color
            }
          }
        }
      }
      entity {
        ... on DraftWorkspace {
          ...WorkflowStatus_data
        }
      }
    }
  }
`;

interface WorkflowTransitionsProps {
  data: WorkflowStatus_data$key;
}

const WorkflowStatus: FunctionComponent<WorkflowTransitionsProps> = ({ data }) => {
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

export const WorkflowTransitions: FunctionComponent<WorkflowTransitionsProps> = ({ data }) => {
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);
  const [validationTransition, setValidationTransition] = useState<string | null>(null);

  const draft = useFragment(workflowStatusFragment, data);
  const { exitDraft } = useSwitchDraft();
  const [commit] = useMutation<WorkflowStatusTriggerMutation>(workflowStatusTriggerMutation);

  if (!draft.workflowInstance || draft.workflowInstance.allowedTransitions.length === 0) {
    return null;
  }

  const { workflowInstance } = draft;
  console.log({ workflowInstance });
  const handleOpen = (event: React.MouseEvent<HTMLButtonElement>) => {
    setAnchorEl(event.currentTarget);
  };

  const handleClose = () => {
    setAnchorEl(null);
  };

  const handleTransition = (eventName: string, actions: readonly string[]) => {
    console.log('Triggering transition:', eventName, 'with actions:', actions);
    if (actions.includes('validateDraft')) {
      handleClose();
      setValidationTransition(eventName);
    } else {
      commit({
        variables: {
          entityId: draft.id,
          eventName,
        },
        onCompleted: () => {
          handleClose();
        },
      });
    }
  };

  const handleValidateDraft = () => {
    if (validationTransition) {
      commit({
        variables: {
          entityId: draft.id,
          eventName: validationTransition,
        },
        onCompleted: (response) => {
          if (response.triggerWorkflowEvent?.success) {
            setValidationTransition(null);
            MESSAGING$.notifySuccess(t_i18n('Draft validation in progress'));
            exitDraft({
              onCompleted: () => {
                if (draft.entity_id) {
                  navigate(`/dashboard/id/${draft.entity_id}`);
                } else {
                  navigate('/dashboard/data/import/draft');
                }
              },
            });
          }
        },
      });
    }
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
            onClick={() => handleTransition(transition.event, transition.actions ?? [])}
          >
            {transition.event}
          </MenuItem>
        ))}
      </Menu>
      <Dialog
        open={Boolean(validationTransition)}
        onClose={() => setValidationTransition(null)}
      >
        <DialogTitle>{t_i18n('Approve draft')}</DialogTitle>
        <DialogContent>
          <DialogContentText>
            {t_i18n('Are you sure you want to approve this draft?')}
            {draft.processingCount > 0 && (
              <div style={{ marginTop: 20 }}>
                <Alert severity="warning">
                  <AlertTitle>{t_i18n('Information')}</AlertTitle>
                  {t_i18n('Some background tasks are still running for this draft. Confirming might lead to inconsistent data.')}
                </Alert>
              </div>
            )}
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setValidationTransition(null)}>
            {t_i18n('Cancel')}
          </Button>
          <Button color="primary" onClick={handleValidateDraft}>
            {t_i18n('Approve')}
          </Button>
        </DialogActions>
      </Dialog>
    </>
  );
};

export default WorkflowStatus;
