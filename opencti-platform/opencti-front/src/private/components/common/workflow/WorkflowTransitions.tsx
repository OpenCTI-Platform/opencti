import Dialog from '@common/dialog/Dialog';
import { ArrowDropDownOutlined, CheckCircle, ErrorOutline, LockOpenOutlined } from '@mui/icons-material';
import { Alert, AlertTitle, Box, CircularProgress, DialogActions, DialogContentText, Divider, Menu, MenuItem, Stack, TextField, Tooltip, Typography } from '@mui/material';
import { Form, Formik } from 'formik';
import { Close } from 'mdi-material-ui';
import React, { FunctionComponent, useEffect, useRef, useState } from 'react';
import { useFragment } from 'react-relay';
import * as Yup from 'yup';
import Button from '../../../../components/common/button/Button';
import { useFormatter } from '../../../../components/i18n';
import ItemStatus from '../../../../components/ItemStatus';
import Transition from '../../../../components/Transition';
import useAuth from '../../../../utils/hooks/useAuth';
import { isBypassUser } from '../../../../utils/hooks/useGranted';
import useHelper from '../../../../utils/hooks/useHelper';
import ObjectOrganizationField from '../../common/form/ObjectOrganizationField';
import { CommentMode } from '../../settings/sub_types/workflow/utils';
import { WorkflowStatus_data$key } from './__generated__/WorkflowStatus_data.graphql';
import { WorkflowStatusStixDomainObject_data$key } from './__generated__/WorkflowStatusStixDomainObject_data.graphql';
import { useTransitionWizard } from './useTransitionWizard';
import { isWorkflowUiEnabledForType } from './workflowFeatureFlag';
import { CLOSING_REASON_MAX_LENGTH, COMMENT_MAX_LENGTH, workflowStatusFragment, workflowStatusStixDomainObjectFragment } from './WorkflowStatus.graphql';

// Task 9: plain-data shape shared by both the DraftWorkspace-bound and generic StixDomainObject-
// bound wrappers below, since DraftWorkspace does not implement StixDomainObject and a single
// Relay fragment cannot cover both — each wrapper resolves its own fragment then delegates to the
// same presentational `WorkflowTransitionsView` component.
interface WorkflowTransitionsProps {
  data: WorkflowStatus_data$key;
  // See WorkflowStatus's `entityType` prop for the rationale (plan.md Task 5, Step 2).
  entityType?: string;
}

interface WorkflowTransitionsForEntityProps {
  data: WorkflowStatusStixDomainObject_data$key;
  entityType: string;
}

// Task 9: a single "step pill" summarizing one of the sections shown in the consolidated Apply
// Transition dialog (per the confirmed design: static/decorative labels, not a real sequential
// wizard — every applicable section is rendered together in the same form).
const StepPill: FunctionComponent<{ label: string }> = ({ label }) => (
  <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
    <CheckCircle fontSize="small" color="success" />
    <Typography variant="caption">{label}</Typography>
  </Box>
);

const WorkflowTransitionsView: FunctionComponent<{
  entityId: string;
  entityNavigationId?: string | null;
  draftId?: string;
  processingCount?: number;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  workflowInstance: any;
  entityType: string;
}> = ({ entityId, entityNavigationId, draftId, processingCount = 0, workflowInstance, entityType }) => {
  const { t_i18n } = useFormatter();
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);
  const { me } = useAuth();
  const isBypass = isBypassUser(me);
  const { isFeatureEnable } = useHelper();

  const {
    wizard,
    setWizard,
    canBypassMandatoryFields,
    approving,
    clearing,
    handleTransition,
    handleApplyWizard,
    handleClear,
    notifyBackgroundTransitionComplete,
  } = useTransitionWizard({ entityId, entityNavigationId, draftId });
  const isPending = workflowInstance?.pendingStatus === 'pending';
  const pendingTransition = workflowInstance?.pendingTransition ?? null;

  const prevIsPendingRef = useRef<boolean>(isPending);
  const prevSyncActionsRef = useRef<readonly { type: string }[] | null>(pendingTransition?.syncActions ?? null);
  useEffect(() => {
    const wasJustPending = prevIsPendingRef.current && !isPending;
    if (wasJustPending) {
      const hadValidateDraft = prevSyncActionsRef.current?.some((a) => a.type === 'validateDraft');
      if (hadValidateDraft) {
        notifyBackgroundTransitionComplete();
      }
    }
    prevIsPendingRef.current = isPending;
    prevSyncActionsRef.current = pendingTransition?.syncActions ?? null;
  });

  if (!workflowInstance || !isWorkflowUiEnabledForType(entityType, isFeatureEnable)) {
    return null;
  }

  const isError = workflowInstance.pendingStatus === 'error';

  const handleOpen = (event: React.MouseEvent<HTMLButtonElement>) => {
    setAnchorEl(event.currentTarget);
  };

  const handleClose = () => {
    setAnchorEl(null);
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
          {isBypass && (
            <Button
              variant="secondary"
              size="small"
              onClick={handleClear}
              disabled={clearing}
              startIcon={<Close />}
            >
              {t_i18n('Clear')}
            </Button>
          )}
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
          <Tooltip title={t_i18n('Force-unlock this transition (admin only). The background task will be orphaned.')}>
            <span>
              <Button
                variant="secondary"
                size="small"
                onClick={handleClear}
                disabled={clearing}
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

  const activeTransition = wizard
    ? workflowInstance.allowedTransitions.find((t) => t.event === wizard.event)
    : null;
  const requiresComment = wizard?.steps.includes('comment') ?? false;
  const requiresOrgPicker = wizard?.steps.includes('org-picker') ?? false;
  const requiresValidate = wizard?.steps.includes('validate') ?? false;
  const requiresClosingReason = wizard?.steps.includes('closing-reason') ?? false;
  const commentRequired = wizard?.commentMode === CommentMode.required && !canBypassMandatoryFields;

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
                transition.isClosingTransition,
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
                onClick={() => {
                  handleClose();
                  handleTransition(
                    transition.event,
                    transition.actions ?? [],
                    transition.comment,
                    transition.requiresShareOrganizationInput,
                    transition.requiresUnshareOrganizationInput,
                    transition.isClosingTransition,
                  );
                }}
              >
                {transition.event}
              </MenuItem>
            ))}
          </Menu>
        </>
      )}
      {/* Task 9: single consolidated Apply Transition dialog — replaces the previous 3 sequential
          dialogs (org-picker / comment / validate). Every applicable section for the selected
          transition is shown together, submitted via one "Apply" button. */}
      <Formik
        initialValues={{
          comment: '',
          closingReason: '',
          shareOrganizations: [] as Array<{ value: string; label: string }>,
          unshareOrganizations: [] as Array<{ value: string; label: string }>,
        }}
        validationSchema={Yup.object({
          comment: commentRequired
            ? Yup.string().trim().required(t_i18n('This field is required'))
            : Yup.string(),
          closingReason: Yup.string(),
          shareOrganizations: Yup.array(),
          unshareOrganizations: Yup.array(),
        })}
        onSubmit={handleApplyWizard}
        enableReinitialize
      >
        {({ submitForm, isSubmitting, resetForm, values, handleChange }) => (
          <Dialog
            open={wizard !== null}
            slotProps={{ paper: { elevation: 1 } }}
            keepMounted={false}
            slots={{ transition: Transition }}
            onClose={() => {
              setWizard(null);
              resetForm();
            }}
            title={t_i18n('Apply transition')}
            size="large"
          >
            <Form>
              {activeTransition?.toStatus && (
                <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                  {t_i18n('Transitioning to')} <ItemStatus status={activeTransition.toStatus} />
                </Typography>
              )}
              <Stack direction="row" spacing={2} sx={{ mb: 2, flexWrap: 'wrap' }}>
                {requiresComment && <StepPill label={t_i18n('Add comment')} />}
                {requiresOrgPicker && <StepPill label={t_i18n('Share with organization')} />}
                {requiresClosingReason && <StepPill label={t_i18n('Closing reason')} />}
                {requiresValidate && <StepPill label={t_i18n('Validate draft')} />}
              </Stack>
              {requiresComment && (
                <>
                  <DialogContentText sx={{ mb: 1 }}>
                    {commentRequired
                      ? t_i18n('A comment is required before changing the status.')
                      : t_i18n('You can optionally add a comment before changing the status.')}
                  </DialogContentText>
                  <TextField
                    autoFocus
                    fullWidth
                    multiline
                    minRows={3}
                    label={t_i18n('Comment')}
                    name="comment"
                    value={values.comment}
                    onChange={handleChange}
                    variant="outlined"
                    size="small"
                    required={commentRequired}
                    slotProps={{ htmlInput: { maxLength: COMMENT_MAX_LENGTH } }}
                    helperText={`${values.comment.length} / ${COMMENT_MAX_LENGTH}`}
                    sx={{ mb: 2 }}
                  />
                </>
              )}
              {requiresClosingReason && (
                <>
                  <DialogContentText sx={{ mb: 1 }}>
                    {t_i18n('You can optionally provide a reason for closing this item.')}
                  </DialogContentText>
                  <TextField
                    fullWidth
                    multiline
                    minRows={3}
                    label={t_i18n('Closing reason')}
                    name="closingReason"
                    value={values.closingReason}
                    onChange={handleChange}
                    variant="outlined"
                    size="small"
                    slotProps={{ htmlInput: { maxLength: CLOSING_REASON_MAX_LENGTH } }}
                    helperText={`${values.closingReason.length} / ${CLOSING_REASON_MAX_LENGTH}`}
                    sx={{ mb: 2 }}
                  />
                </>
              )}
              {requiresOrgPicker && (
                <>
                  {wizard?.requiresShareOrg && (
                    <>
                      <DialogContentText sx={{ mb: 1 }}>
                        {t_i18n('Select the organizations to share the content with during this transition.')}
                      </DialogContentText>
                      <ObjectOrganizationField
                        name="shareOrganizations"
                        label={t_i18n('Organizations to share with')}
                        multiple={true}
                        style={{ width: '100%', marginBottom: 16 }}
                      />
                    </>
                  )}
                  {wizard?.requiresUnshareOrg && (
                    <>
                      <DialogContentText sx={{ mb: 1 }}>
                        {t_i18n('Select the organizations to unshare the content from during this transition.')}
                      </DialogContentText>
                      <ObjectOrganizationField
                        name="unshareOrganizations"
                        label={t_i18n('Organizations to unshare from')}
                        multiple={true}
                        style={{ width: '100%', marginBottom: 16 }}
                      />
                    </>
                  )}
                </>
              )}
              {requiresValidate && (
                <>
                  <DialogContentText sx={{ mb: 1 }}>
                    {t_i18n('Do you want to approve this draft and send it to ingestion?')}
                  </DialogContentText>
                  {processingCount > 0 && (
                    <Alert sx={{ mb: 2 }} severity="warning">
                      <AlertTitle>{t_i18n('Ongoing processes')}</AlertTitle>
                      {t_i18n('There are processes still running that could impact the data of the draft. '
                        + 'By approving the draft now, the remaining changes that would have been applied by those processes will be ignored.')}
                    </Alert>
                  )}
                </>
              )}
              <DialogActions>
                <Button
                  variant="secondary"
                  onClick={() => {
                    setWizard(null);
                    resetForm();
                  }}
                >
                  {t_i18n('Cancel')}
                </Button>
                <Button
                  onClick={submitForm}
                  disabled={isSubmitting || approving || (commentRequired && values.comment.trim() === '')}
                >
                  {t_i18n('Apply')}
                </Button>
              </DialogActions>
            </Form>
          </Dialog>
        )}
      </Formik>
    </>
  );
};

export const WorkflowTransitions: FunctionComponent<WorkflowTransitionsProps> = ({ data, entityType = 'DraftWorkspace' }) => {
  const { isFeatureEnable } = useHelper();
  const draft = useFragment(workflowStatusFragment, data);
  if (!draft.workflowInstance || !isWorkflowUiEnabledForType(entityType, isFeatureEnable)) {
    return null;
  }
  return (
    <WorkflowTransitionsView
      entityId={draft.id}
      entityNavigationId={draft.entity_id}
      draftId={draft.id}
      processingCount={draft.processingCount}
      workflowInstance={draft.workflowInstance}
      entityType={entityType}
    />
  );
};

// Task 9: generic counterpart for any StixDomainObject-implementing entity type (Report, Malware,
// Incident, etc.), gated by the ENTITIES_WORKFLOW feature flag (isWorkflowUiEnabledForType).
export const WorkflowTransitionsForEntity: FunctionComponent<WorkflowTransitionsForEntityProps> = ({ data, entityType }) => {
  const { isFeatureEnable } = useHelper();
  const entity = useFragment(workflowStatusStixDomainObjectFragment, data);
  if (!entity.workflowInstance || !isWorkflowUiEnabledForType(entityType, isFeatureEnable)) {
    return null;
  }
  return (
    <WorkflowTransitionsView
      entityId={entity.id}
      entityNavigationId={entity.id}
      workflowInstance={entity.workflowInstance}
      entityType={entityType}
    />
  );
};

export default WorkflowTransitions;
