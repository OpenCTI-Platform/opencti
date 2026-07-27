import React, { FunctionComponent, useEffect, useRef, useState } from 'react';
import { useFragment } from 'react-relay';
import { Alert, AlertTitle, Box, CircularProgress, DialogActions, DialogContentText, Divider, Menu, MenuItem, TextField, Tooltip, Typography } from '@mui/material';
import { ArrowDropDownOutlined, ErrorOutline, LockOpenOutlined } from '@mui/icons-material';
import { Form, Formik } from 'formik';
import * as Yup from 'yup';
import ObjectOrganizationField from '../../common/form/ObjectOrganizationField';
import Button from '../../../../components/common/button/Button';
import { WorkflowStatus_data$key } from './__generated__/WorkflowStatus_data.graphql';
import { useFormatter } from '../../../../components/i18n';
import Transition from '../../../../components/Transition';
import Dialog from '@common/dialog/Dialog';
import { CommentMode } from '../../settings/sub_types/workflow/utils';
import { workflowStatusFragment, COMMENT_MAX_LENGTH } from './WorkflowStatus.graphql';
import { useTransitionWizard } from './useTransitionWizard';
import { isBypassUser } from '../../../../utils/hooks/useGranted';
import useAuth from '../../../../utils/hooks/useAuth';
import { Close } from 'mdi-material-ui';

interface WorkflowTransitionsProps {
  data: WorkflowStatus_data$key;
}

export const WorkflowTransitions: FunctionComponent<WorkflowTransitionsProps> = ({ data }) => {
  const { t_i18n } = useFormatter();
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);
  const { me } = useAuth();
  const isBypass = isBypassUser(me);

  const draft = useFragment(workflowStatusFragment, data);
  const {
    wizard,
    setWizard,
    commentValue,
    setCommentValue,
    currentStep,
    canBypassMandatoryFields,
    approving,
    clearing,
    handleTransition,
    handleOrgPickerSubmit,
    handleConfirmComment,
    handleValidateDraft,
    handleClear,
    notifyBackgroundTransitionComplete,
  } = useTransitionWizard({ entityId: draft.id, entityNavigationId: draft.entity_id, draftId: draft.id });

  const workflowInstance = draft.workflowInstance;
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
                onClick={() => {
                  handleClose();
                  handleTransition(
                    transition.event,
                    transition.actions ?? [],
                    transition.comment,
                    transition.requiresShareOrganizationInput,
                    transition.requiresUnshareOrganizationInput,
                  );
                }}
              >
                {transition.event}
              </MenuItem>
            ))}
          </Menu>
        </>
      )}
      {/* Step 1: org picker */}
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
            open={currentStep === 'org-picker'}
            slotProps={{ paper: { elevation: 1 } }}
            keepMounted={false}
            slots={{ transition: Transition }}
            onClose={() => {
              setWizard(null);
              resetForm();
            }}
            title={t_i18n('Select organizations')}
            size="small"
          >
            <Form>
              {wizard?.requiresShareOrg && (
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
              {wizard?.requiresUnshareOrg && (
                <>
                  <DialogContentText sx={{ mb: 2, mt: wizard?.requiresShareOrg ? 2 : 0 }}>
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
                    setWizard(null);
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
      {/* Step 2: comment */}
      <Dialog
        open={currentStep === 'comment'}
        slotProps={{ paper: { elevation: 1 } }}
        keepMounted={false}
        slots={{ transition: Transition }}
        onClose={() => setWizard(null)}
        title={t_i18n('Add a comment')}
        size="large"
      >
        <DialogContentText sx={{ marginBottom: 2 }}>
          {wizard?.commentMode === CommentMode.required
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
          required={wizard?.commentMode === CommentMode.required}
          slotProps={{ htmlInput: { maxLength: COMMENT_MAX_LENGTH } }}
          helperText={`${commentValue.length} / ${COMMENT_MAX_LENGTH}`}
        />
        <DialogActions>
          <Button
            variant="secondary"
            onClick={() => setWizard(null)}
          >
            {t_i18n('Cancel')}
          </Button>
          <Button
            onClick={handleConfirmComment}
            disabled={wizard?.commentMode === CommentMode.required && commentValue.trim() === '' && !canBypassMandatoryFields}
          >
            {t_i18n('Confirm')}
          </Button>
        </DialogActions>
      </Dialog>
      {/* Step 3: validate draft */}
      <Dialog
        open={currentStep === 'validate'}
        slotProps={{ paper: { elevation: 1 } }}
        keepMounted={false}
        slots={{ transition: Transition }}
        onClose={() => setWizard(null)}
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
            onClick={() => setWizard(null)}
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
    </>
  );
};

export default WorkflowTransitions;
