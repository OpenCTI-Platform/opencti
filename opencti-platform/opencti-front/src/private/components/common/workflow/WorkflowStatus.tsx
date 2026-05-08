import React, { FunctionComponent, useEffect, useRef, useState } from 'react';
import { graphql, useFragment, useMutation } from 'react-relay';
import { Alert, AlertTitle, Box, CircularProgress, DialogActions, DialogContentText, Divider, Menu, MenuItem, TextField, Tooltip, Typography } from '@mui/material';
import { ArrowDropDownOutlined, ErrorOutline, Refresh, LockOpenOutlined, CommentOutlined } from '@mui/icons-material';
import { Form, Formik } from 'formik';
import * as Yup from 'yup';
import ObjectOrganizationField from '../../common/form/ObjectOrganizationField';
import { WorkflowStatusClearMutation } from './__generated__/WorkflowStatusClearMutation.graphql';
import ItemStatus from '../../../../components/ItemStatus';
import Button from '../../../../components/common/button/Button';
import { WorkflowStatus_data$key } from './__generated__/WorkflowStatus_data.graphql';
import { WorkflowStatusTriggerMutation } from './__generated__/WorkflowStatusTriggerMutation.graphql';
import { WorkflowStatusRetryMutation } from './__generated__/WorkflowStatusRetryMutation.graphql';
import { useFormatter } from '../../../../components/i18n';
import useSwitchDraft from '../../drafts/useSwitchDraft';
import { MESSAGING$ } from '../../../../relay/environment';
import { useNavigate } from 'react-router-dom';
import Transition from '../../../../components/Transition';
import Dialog from '@common/dialog/Dialog';
import useGranted, { KNOWLEDGE_KNUPDATE_KNBYPASSFIELDS } from '../../../../utils/hooks/useGranted';
import { CommentMode } from '../../settings/sub_types/workflow/utils';

const COMMENT_MAX_LENGTH = 1000; // Keep in sync with COMMENT_MAX_LENGTH in opencti-graphql/src/modules/workflow/api/workflow-resolvers.ts

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
      lastHistoryEntry {
        comment
      }  
      pendingStatus
      pendingError
      pendingTransition {
        event
        toState
        triggeredAt
        syncActions {
          type
        }
        asyncActions {
          id
          type
          status
          processedCount
          expectedCount
          errors {
            message
          }
        }
      }
      allowedTransitions {
        event
        toState
        actions
        comment
        requiresShareOrganizationInput
        requiresUnshareOrganizationInput
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
mutation WorkflowStatusTriggerMutation($entityId: String!, $eventName: String!, $comment: String, $runtimeParams: JSON) {
  triggerWorkflowEvent(entityId: $entityId, eventName: $eventName, comment: $comment, runtimeParams: $runtimeParams) {
      success
      reason
      newState
      executionStatus
      instance {
        id
        currentState
        pendingStatus
        pendingError
        pendingTransition {
          event
          toState
          triggeredAt
          asyncActions {
            id
            type
            status
            processedCount
            expectedCount
            errors {
              message
            }
          }
        }
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
          comment
          requiresShareOrganizationInput
          requiresUnshareOrganizationInput
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

const workflowStatusRetryMutation = graphql`
  mutation WorkflowStatusRetryMutation($entityId: String!) {
    retryPendingWorkflowTransitionActions(entityId: $entityId) {
      success
      reason
      executionStatus
      entity {
        ... on DraftWorkspace {
          ...WorkflowStatus_data
        }
      }
    }
  }
`;

const workflowStatusClearMutation = graphql`
  mutation WorkflowStatusClearMutation($entityId: String!) {
    clearWorkflowPendingState(entityId: $entityId) {
      id
      pendingStatus
      pendingError
      pendingTransition {
        event
        toState
        triggeredAt
        asyncActions {
          id
          type
          status
          processedCount
          expectedCount
          errors {
            message
          }
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
  const lastComment = workflowInstance.lastHistoryEntry?.comment ?? null;

  return (
    <>
      {lastComment && (
        <Tooltip title={lastComment} arrow>
          <CommentOutlined fontSize="small" sx={{ marginRight: 0.5, color: 'text.secondary' }} />
        </Tooltip>
      )}
      <ItemStatus status={currentStatus} />
    </>
  );
};

export const WorkflowTransitions: FunctionComponent<WorkflowTransitionsProps> = ({ data }) => {
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);
  const [validationTransition, setValidationTransition] = useState<{ event: string; actions: readonly string[]; runtimeParams?: Record<string, unknown> } | null>(null);
  const [commentDialogTransition, setCommentDialogTransition] = useState<{
    event: string;
    actions: readonly string[];
    comment: string;
  } | null>(null);
  const [commentValue, setCommentValue] = useState('');

  const draft = useFragment(workflowStatusFragment, data);
  const { exitDraft } = useSwitchDraft();
  const canBypassMandatoryFields = useGranted([KNOWLEDGE_KNUPDATE_KNBYPASSFIELDS]);
  const [orgPickerTransition, setOrgPickerTransition] = useState<{
    event: string;
    actions: readonly string[];
    requiresShareOrg: boolean;
    requiresUnshareOrg: boolean;
  } | null>(null);

  const [commit, approving] = useMutation<WorkflowStatusTriggerMutation>(workflowStatusTriggerMutation);
  const [commitRetry, retrying] = useMutation<WorkflowStatusRetryMutation>(workflowStatusRetryMutation);
  const [commitClear, clearing] = useMutation<WorkflowStatusClearMutation>(workflowStatusClearMutation);

  const workflowInstance = draft.workflowInstance;
  const isPending = workflowInstance?.pendingStatus === 'pending';
  const pendingTransition = workflowInstance?.pendingTransition ?? null;

  // Track prev isPending to detect when a background transition completes.
  // When isPending goes false and the previous pendingTransition had validateDraft in syncActions,
  // automatically exit the draft (mirrors what fireTransition does for sync-only completions).
  const prevIsPendingRef = useRef<boolean>(isPending);
  const prevSyncActionsRef = useRef<readonly { type: string }[] | null>(pendingTransition?.syncActions ?? null);
  useEffect(() => {
    const wasJustPending = prevIsPendingRef.current && !isPending;
    if (wasJustPending) {
      const hadValidateDraft = prevSyncActionsRef.current?.some((a) => a.type === 'validateDraft');
      if (hadValidateDraft) {
        MESSAGING$.notifySuccess(t_i18n('Draft validated successfully'));
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
    }
    prevIsPendingRef.current = isPending;
    prevSyncActionsRef.current = pendingTransition?.syncActions ?? null;
  });

  if (!workflowInstance) {
    return null;
  }

  const isError = workflowInstance.pendingStatus === 'error';

  const handleOpen = (event: React.MouseEvent<HTMLButtonElement>) => {
    setAnchorEl(event.currentTarget);
  };

  const handleClose = () => {
    setAnchorEl(null);
  };

  const fireTransition = (
    eventName: string,
    actions: readonly string[],
    runtimeParams?: Record<string, unknown>,
    comment?: string,
  ) => {
    commit({
      variables: { entityId: draft.id, eventName, runtimeParams, comment },
      onCompleted: (response) => {
        handleClose();
        if (
          response.triggerWorkflowEvent?.success
          && response.triggerWorkflowEvent.executionStatus !== 'pending'
          && actions.includes('validateDraft')
        ) {
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
        } else if (response.triggerWorkflowEvent?.executionStatus === 'pending') {
          MESSAGING$.notifySuccess(t_i18n('Workflow transition started in background'));
        }
      },
    });
  };

  const showValidationDialogOrFireTransition = (
    eventName: string,
    actions: readonly string[],
    comment?: string,
    runtimeParams?: Record<string, unknown>,
  ) => {
    if (actions.includes('validateDraft')) {
      setValidationTransition({ event: eventName, actions, runtimeParams });
    } else {
      fireTransition(eventName, actions, runtimeParams, comment);
    }
  };

  const handleTransition = (
    eventName: string,
    actions: readonly string[],
    comment?: string | null,
    requiresShareOrg?: boolean | null,
    requiresUnshareOrg?: boolean | null,
  ) => {
    handleClose();
    const needsOrgInput = requiresShareOrg || requiresUnshareOrg;
    if (needsOrgInput) {
      setOrgPickerTransition({
        event: eventName,
        actions,
        requiresShareOrg: !!requiresShareOrg,
        requiresUnshareOrg: !!requiresUnshareOrg,
      });
      return;
    }
    if (comment === CommentMode.allowed || comment === CommentMode.required) {
      setCommentValue('');
      setCommentDialogTransition({ event: eventName, actions, comment });
      return;
    }
    showValidationDialogOrFireTransition(eventName, actions);
  };

  const handleConfirmComment = () => {
    if (!commentDialogTransition) return;
    const { event, actions } = commentDialogTransition;
    setCommentDialogTransition(null);
    setCommentValue('');
    showValidationDialogOrFireTransition(event, actions, commentValue.trim() || undefined);
  };

  const handleValidateDraft = () => {
    if (validationTransition) {
      fireTransition(validationTransition.event, validationTransition.actions, validationTransition.runtimeParams);
      setValidationTransition(null);
    }
  };

  const handleOrgPickerSubmit = (
    values: { shareOrganizations: Array<{ value: string }>; unshareOrganizations: Array<{ value: string }> },
    { resetForm }: { resetForm: () => void },
  ) => {
    if (orgPickerTransition) {
      const rp: Record<string, string[]> = {};
      if (orgPickerTransition.requiresShareOrg) rp.shareOrganizationIds = values.shareOrganizations.map((o) => o.value);
      if (orgPickerTransition.requiresUnshareOrg) rp.unshareOrganizationIds = values.unshareOrganizations.map((o) => o.value);
      const { event, actions } = orgPickerTransition;
      setOrgPickerTransition(null);
      resetForm();
      // If this transition also validates the draft, chain to the confirmation dialog.
      if (actions.includes('validateDraft')) {
        setValidationTransition({ event, actions, runtimeParams: rp });
      } else {
        fireTransition(event, actions, rp);
      }
    }
  };

  const handleRetry = () => {
    commitRetry({
      variables: { entityId: draft.id },
      onCompleted: (response) => {
        if (response.retryPendingWorkflowTransitionActions?.success) {
          MESSAGING$.notifySuccess(t_i18n('Workflow actions retried'));
        }
      },
    });
  };

  const handleClear = () => {
    commitClear({
      variables: { entityId: draft.id },
      onCompleted: () => {
        MESSAGING$.notifySuccess(t_i18n('Pending workflow state cleared'));
      },
    });
  };

  // Pending state UI
  if (isPending && pendingTransition) {
    const totalExpected = pendingTransition.asyncActions.reduce((sum, s) => sum + (s.expectedCount ?? 0), 0);
    const totalProcessed = pendingTransition.asyncActions.reduce((sum, s) => sum + (s.processedCount ?? 0), 0);
    return (
      <>
        <Divider orientation="vertical" flexItem sx={{ marginRight: 1 }} />
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <Typography variant="caption" noWrap>
            {pendingTransition.event}
          </Typography>
          {totalExpected > 0 && (
            <Typography variant="caption" color="text.secondary" noWrap>
              {totalProcessed} / {totalExpected}
            </Typography>
          )}
          <CircularProgress size={14} thickness={5} />
        </Box>
      </>
    );
  }

  // Error state UI
  if (isError) {
    return (
      <>
        <Divider orientation="vertical" flexItem sx={{ marginRight: 1 }} />
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <Tooltip title={workflowInstance.pendingError ?? t_i18n('One or more async workflow actions failed')}>
            <ErrorOutline color="error" fontSize="small" />
          </Tooltip>
          <Typography variant="caption" color="error">
            {t_i18n('Transition failed')}
          </Typography>
          <Button
            variant="secondary"
            size="small"
            onClick={handleRetry}
            disabled={retrying || clearing}
            startIcon={<Refresh />}
          >
            {t_i18n('Retry')}
          </Button>
          <Tooltip title={t_i18n('Force-unlock this transition (admin only). The background task will be orphaned.')}>
            <span>
              <Button
                variant="secondary"
                size="small"
                onClick={handleClear}
                disabled={clearing || retrying}
                startIcon={<LockOpenOutlined />}
              >
                {t_i18n('Clear')}
              </Button>
            </span>
          </Tooltip>
        </Box>
      </>
    );
  }

  if (workflowInstance.allowedTransitions.length === 0) {
    return null;
  }

  return (
    <>
      <Divider orientation="vertical" flexItem sx={{ marginRight: 1 }} />
      {workflowInstance.allowedTransitions.length < 3 ? (
        <>
          {workflowInstance.allowedTransitions.map((transition) => (
            <Button
              key={transition.event}
              variant="primary"
              onClick={() => handleTransition(
                transition.event,
                transition.actions ?? [],
                transition.comment,
                transition.requiresShareOrganizationInput,
                transition.requiresUnshareOrganizationInput,
              )}
              disabled={approving}
            >
              {transition.event}
            </Button>
          ))}
        </>
      ) : (
        <>
          <Button
            variant="primary"
            onClick={handleOpen}
            endIcon={<ArrowDropDownOutlined />}
            disabled={approving}
          >
            {t_i18n('Next status')}
          </Button>
          <Menu anchorEl={anchorEl} open={Boolean(anchorEl)} onClose={handleClose}>
            {workflowInstance.allowedTransitions.map((transition) => (
              <MenuItem
                key={transition.event}
                onClick={() => handleTransition(
                  transition.event,
                  transition.actions ?? [],
                  transition.comment,
                  transition.requiresShareOrganizationInput,
                  transition.requiresUnshareOrganizationInput,
                )}
              >
                {transition.event}
              </MenuItem>
            ))}
          </Menu>
        </>
      )}
      {/* Comment dialog */}
      <Dialog
        open={Boolean(commentDialogTransition)}
        slotProps={{ paper: { elevation: 1 } }}
        keepMounted={false}
        slots={{ transition: Transition }}
        onClose={() => setCommentDialogTransition(null)}
        title={t_i18n('Add a comment')}
        size="large"
      >
        <DialogContentText sx={{ marginBottom: 2 }}>
          {commentDialogTransition?.comment === CommentMode.required
            ? t_i18n('A comment is required before changing the status.')
            : t_i18n('You can optionally add a comment before changing the status.')}
        </DialogContentText>
        <TextField
          autoFocus
          fullWidth
          multiline
          minRows={3}
          label={t_i18n('Comment')}
          value={commentValue}
          onChange={(e) => setCommentValue(e.target.value)}
          variant="outlined"
          size="small"
          required={commentDialogTransition?.comment === CommentMode.required}
          slotProps={{ htmlInput: { maxLength: COMMENT_MAX_LENGTH } }}
          helperText={`${commentValue.length} / ${COMMENT_MAX_LENGTH}`}
        />
        <DialogActions>
          <Button
            variant="secondary"
            onClick={() => setCommentDialogTransition(null)}
          >
            {t_i18n('Cancel')}
          </Button>
          <Button
            onClick={handleConfirmComment}
            disabled={commentDialogTransition?.comment === CommentMode.required && commentValue.trim() === '' && !canBypassMandatoryFields}
          >
            {t_i18n('Confirm')}
          </Button>
        </DialogActions>
      </Dialog>
      {/* Validation dialog */}
      <Dialog
        open={Boolean(validationTransition)}
        slotProps={{ paper: { elevation: 1 } }}
        keepMounted={false}
        slots={{ transition: Transition }}
        onClose={() => setValidationTransition(null)}
        title={t_i18n('Are you sure?')}
        size="small"
      >
        <DialogContentText>
          {t_i18n('Do you want to approve this draft and send it to ingestion?')}
          {draft.processingCount > 0 && (
            <Alert sx={{ marginTop: 1 }} severity="warning">
              <AlertTitle>{t_i18n('Ongoing processes')}</AlertTitle>
              {t_i18n('There are processes still running that could impact the data of the draft. '
                + 'By approving the draft now, the remaining changes that would have been applied by those processes will be ignored.')}
            </Alert>
          )}
        </DialogContentText>
        <DialogActions>
          <Button
            variant="secondary"
            onClick={() => setValidationTransition(null)}
          >
            {t_i18n('Cancel')}
          </Button>
          <Button
            onClick={handleValidateDraft}
            disabled={approving}
          >
            {t_i18n('Approve')}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Organization picker dialog for transitions requiring org input */}
      <Formik
        initialValues={{
          shareOrganizations: [] as Array<{ value: string; label: string }>,
          unshareOrganizations: [] as Array<{ value: string; label: string }>,
        }}
        validationSchema={Yup.object({
          shareOrganizations: Yup.array(),
          unshareOrganizations: Yup.array(),
        })}
        onSubmit={handleOrgPickerSubmit}
        enableReinitialize
      >
        {({ submitForm, isSubmitting, resetForm }) => (
          <Dialog
            open={Boolean(orgPickerTransition)}
            slotProps={{ paper: { elevation: 1 } }}
            keepMounted={false}
            slots={{ transition: Transition }}
            onClose={() => {
              setOrgPickerTransition(null);
              resetForm();
            }}
            title={t_i18n('Select organizations')}
            size="small"
          >
            <Form>
              {orgPickerTransition?.requiresShareOrg && (
                <>
                  <DialogContentText sx={{ mb: 2 }}>
                    {t_i18n('Select the organizations to share the draft content with during this transition.')}
                  </DialogContentText>
                  <ObjectOrganizationField
                    name="shareOrganizations"
                    label={t_i18n('Organizations to share with')}
                    multiple={true}
                    style={{ width: '100%' }}
                  />
                </>
              )}
              {orgPickerTransition?.requiresUnshareOrg && (
                <>
                  <DialogContentText sx={{ mb: 2, mt: orgPickerTransition?.requiresShareOrg ? 2 : 0 }}>
                    {t_i18n('Select the organizations to unshare the draft content from during this transition.')}
                  </DialogContentText>
                  <ObjectOrganizationField
                    name="unshareOrganizations"
                    label={t_i18n('Organizations to unshare from')}
                    multiple={true}
                    style={{ width: '100%' }}
                  />
                </>
              )}
              <DialogActions>
                <Button
                  variant="secondary"
                  onClick={() => {
                    setOrgPickerTransition(null);
                    resetForm();
                  }}
                >
                  {t_i18n('Cancel')}
                </Button>
                <Button
                  onClick={submitForm}
                  disabled={isSubmitting || approving}
                >
                  {t_i18n('Confirm')}
                </Button>
              </DialogActions>
            </Form>
          </Dialog>
        )}
      </Formik>
    </>
  );
};

export default WorkflowStatus;
