import React, { FunctionComponent, useEffect, useRef, useState } from 'react';
import { fetchQuery, useFragment, useRelayEnvironment } from 'react-relay';
import type { Subscription } from 'relay-runtime';
import { Menu, MenuContent, MenuItem, MenuTrigger } from '@filigran/design-system';
import { Alert, AlertTitle, Box, CircularProgress, DialogActions, DialogContentText, Tooltip, Typography } from '@mui/material';
import { ArrowDropDownOutlined, ArrowDropUpOutlined, ErrorOutline, LockOpenOutlined } from '@mui/icons-material';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import ObjectOrganizationField from '../../common/form/ObjectOrganizationField';
import { WorkflowStatus_data$data, WorkflowStatus_data$key } from './__generated__/WorkflowStatus_data.graphql';
import { useFormatter } from '../../../../components/i18n';
import Transition from '../../../../components/Transition';
import Dialog from '@common/dialog/Dialog';
import { CommentMode } from '../../settings/sub_types/workflow/utils';
import { workflowStatusFragment, workflowStatusStixDomainObjectFragment, workflowStatusEntityQuery, COMMENT_MAX_LENGTH } from './WorkflowStatus.graphql';
import { TransitionFormValues, useTransitionWizard } from './useTransitionWizard';
import { isBypassUser } from '../../../../utils/hooks/useGranted';
import useAuth from '../../../../utils/hooks/useAuth';
import { Close } from 'mdi-material-ui';
import useHelper from '../../../../utils/hooks/useHelper';
import { isWorkflowUiEnabledForType } from './workflowFeatureFlag';
import TextareaField from '../../../../components/TextareaField';
import type { WorkflowStatusStixDomainObject_data$key } from './__generated__/WorkflowStatusStixDomainObject_data.graphql';
import type { WorkflowStatusEntityQuery } from './__generated__/WorkflowStatusEntityQuery.graphql';
import useInterval from '../../../../utils/hooks/useInterval';
import { FIVE_SECONDS } from '../../../../utils/Time';
import { useGetCurrentUserAccessRight } from '../../../../utils/authorizedMembers';
import { relayErrorHandling } from '../../../../relay/environment';
import WorkflowBypassStatus from './WorkflowBypassStatus';
import Button from '@common/button/Button';

interface WorkflowTransitionsProps {
  data: WorkflowStatus_data$key;
  entityType?: string;
}

interface WorkflowTransitionsViewProps {
  entityId: string;
  entityNavigationId?: string | null;
  draftId?: string;
  processingCount?: number;
  workflowInstance: WorkflowStatus_data$data['workflowInstance'];
  entityType: string;
  refreshing?: boolean;
  onCompleted?: () => void;
}

const WorkflowTransitionsView: FunctionComponent<WorkflowTransitionsViewProps> = ({
  entityId,
  entityNavigationId,
  draftId,
  processingCount = 0,
  workflowInstance,
  entityType,
  refreshing = false,
  onCompleted,
}) => {
  const { t_i18n } = useFormatter();
  const { isFeatureEnable } = useHelper();
  const [menuOpen, setMenuOpen] = useState(false);
  const { me } = useAuth();
  const isBypass = isBypassUser(me);

  const isPending = workflowInstance?.pendingStatus === 'pending';
  const isError = workflowInstance?.pendingStatus === 'error';
  const {
    wizard,
    setWizard,
    canBypassMandatoryFields,
    approving: submitting,
    clearing,
    handleTransition,
    handleApplyWizard,
    handleClear,
    notifyBackgroundTransitionComplete,
  } = useTransitionWizard({ entityId, entityNavigationId, draftId, isPending, onCompleted });
  const approving = submitting || refreshing;

  const pendingTransition = workflowInstance?.pendingTransition ?? null;

  const prevIsPendingRef = useRef<boolean>(isPending);
  const prevPendingTransitionRef = useRef(pendingTransition);
  useEffect(() => {
    const wasJustPending = prevIsPendingRef.current && !isPending;
    if (draftId && wasJustPending && !isError && workflowInstance?.currentState === prevPendingTransitionRef.current?.toState) {
      const hadValidateDraft = prevPendingTransitionRef.current?.syncActions?.some((action) => action.type === 'validateDraft');
      if (hadValidateDraft) {
        notifyBackgroundTransitionComplete();
      }
    }
    prevIsPendingRef.current = isPending;
    prevPendingTransitionRef.current = pendingTransition;
  });

  if (!workflowInstance || !isWorkflowUiEnabledForType(entityType, isFeatureEnable)) {
    return null;
  }

  if (isPending) {
    const totalExpected = pendingTransition?.asyncActions.reduce((sum, action) => sum + (action.expectedCount ?? 0), 0) ?? 0;
    const totalProcessed = pendingTransition?.asyncActions.reduce((sum, action) => sum + (action.processedCount ?? 0), 0) ?? 0;
    return (
      <>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <Typography variant="caption" noWrap>
            {pendingTransition?.event}
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
              disabled={clearing || approving}
              startIcon={<Close fontSize="small" />}
            >
              {t_i18n('Clear')}
            </Button>
          )}
        </Box>
      </>
    );
  }

  if (isError) {
    return (
      <>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <Tooltip title={workflowInstance.pendingError ?? t_i18n('One or more async workflow actions failed')}>
            <ErrorOutline color="error" fontSize="small" />
          </Tooltip>
          <Typography variant="caption" color="error">
            {t_i18n('Transition failed')}
          </Typography>
          {isBypass && (
            <Tooltip title={t_i18n('Force-unlock this transition (admin only). The background task will be orphaned.')}>
              <span>
                <Button
                  variant="secondary"
                  size="small"
                  onClick={handleClear}
                  disabled={clearing || approving}
                  startIcon={<LockOpenOutlined fontSize="small" />}
                >
                  {t_i18n('Clear')}
                </Button>
              </span>
            </Tooltip>
          )}
        </Box>
      </>
    );
  }

  if (workflowInstance.allowedTransitions.length === 0) {
    return null;
  }

  return (
    <>
      {workflowInstance.allowedTransitions.length > 1 ? (
        <Menu open={menuOpen} onOpenChange={setMenuOpen}>
          <MenuTrigger asChild>
            <Button
              disabled={approving || clearing || !!wizard}
              endIcon={!menuOpen ? (<ArrowDropDownOutlined />) : (<ArrowDropUpOutlined />)}
            >
              {t_i18n('Next status')}
            </Button>
          </MenuTrigger>
          <MenuContent
            align="start"
            sideOffset={6}
            style={{ minWidth: 'var(--radix-dropdown-menu-trigger-width)', maxWidth: 'calc(100vw - 32px)' }}
          >
            {workflowInstance.allowedTransitions.map((transition) => {
              const actionCount = transition.actions?.length ?? 0;
              return (
                <MenuItem
                  key={transition.event}
                  disabled={approving || clearing || !!wizard}
                  onSelect={() => handleTransition(
                    transition.event,
                    transition.actions ?? [],
                    transition.comment,
                    transition.requiresShareOrganizationInput,
                    transition.requiresUnshareOrganizationInput,
                  )}
                  style={{ display: 'flex', justifyContent: 'space-between', gap: 16, height: 'auto', minHeight: 36, whiteSpace: 'normal' }}
                  endIcon={actionCount > 0 ? (
                    <span style={{ fontSize: 12, color: 'var(--text-default-secondary)', whiteSpace: 'nowrap' }}>
                      (+{actionCount} {t_i18n(actionCount === 1 ? 'action required' : 'actions required')})
                    </span>
                  ) : undefined}
                >
                  <span style={{ overflowWrap: 'anywhere' }}>{transition.event}</span>
                </MenuItem>
              );
            })}
          </MenuContent>
        </Menu>
      ) : (
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
              disabled={approving || clearing || !!wizard}
            >
              {transition.event}
            </Button>
          ))}
        </>
      )}
      {wizard && (
        <Formik<TransitionFormValues>
          initialValues={{ comment: '', shareOrganizations: [], unshareOrganizations: [] }}
          validationSchema={Yup.object({
            comment: wizard.commentMode === CommentMode.required && !canBypassMandatoryFields
              ? Yup.string().trim().required(t_i18n('This field is required')).max(COMMENT_MAX_LENGTH)
              : Yup.string().trim().max(COMMENT_MAX_LENGTH),
            shareOrganizations: Yup.array(),
            unshareOrganizations: Yup.array(),
          })}
          onSubmit={handleApplyWizard}
          validateOnMount
        >
          {({ values, isSubmitting, isValid }) => {
            const disabled = isSubmitting || approving || clearing;
            const missingComment = wizard.commentMode === CommentMode.required && !canBypassMandatoryFields && !values.comment.trim();
            return (
              <Dialog
                open
                slotProps={{ paper: { elevation: 1 } }}
                keepMounted={false}
                slots={{ transition: Transition }}
                onClose={() => {
                  if (!disabled) setWizard(null);
                }}
                title={wizard.event}
                size="small"
              >
                <Form noValidate>
                  <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                    {wizard.requiresShareOrg && (
                      <ObjectOrganizationField
                        name="shareOrganizations"
                        label={t_i18n('Organizations to share with')}
                        multiple={true}
                        disabled={disabled}
                        style={{ width: '100%' }}
                      />
                    )}
                    {wizard.requiresUnshareOrg && (
                      <ObjectOrganizationField
                        name="unshareOrganizations"
                        label={t_i18n('Organizations to unshare from')}
                        multiple={true}
                        disabled={disabled}
                        style={{ width: '100%' }}
                      />
                    )}
                    {(wizard.commentMode === CommentMode.allowed || wizard.commentMode === CommentMode.required) && (
                      <>
                        <DialogContentText>
                          {wizard.commentMode === CommentMode.required
                            ? t_i18n('A comment is required before changing the status.')
                            : t_i18n('You can optionally add a comment before changing the status.')}
                        </DialogContentText>
                        <Field
                          component={TextareaField}
                          name="comment"
                          label={t_i18n('Comment')}
                          required={wizard.commentMode === CommentMode.required && !canBypassMandatoryFields}
                          disabled={disabled}
                          rows={3}
                          maxLength={COMMENT_MAX_LENGTH}
                          helperText={`${values.comment.length} / ${COMMENT_MAX_LENGTH}`}
                        />
                      </>
                    )}
                    {wizard.requiresValidation && (
                      <>
                        <DialogContentText>{t_i18n('Do you want to approve this draft and send it to ingestion?')}</DialogContentText>
                        {processingCount > 0 && (
                          <Alert severity="warning">
                            <AlertTitle>{t_i18n('Ongoing processes')}</AlertTitle>
                            {t_i18n('There are processes still running that could impact the data of the draft. '
                              + 'By approving the draft now, the remaining changes that would have been applied by those processes will be ignored.')}
                          </Alert>
                        )}
                      </>
                    )}
                  </Box>
                  <DialogActions>
                    <Button variant="secondary" onClick={() => setWizard(null)} disabled={disabled}>
                      {t_i18n('Cancel')}
                    </Button>
                    <Button type="submit" disabled={disabled || !isValid || !!missingComment || values.comment.length > COMMENT_MAX_LENGTH}>
                      {wizard.requiresValidation ? t_i18n('Approve') : t_i18n('Confirm')}
                    </Button>
                  </DialogActions>
                </Form>
              </Dialog>
            );
          }}
        </Formik>
      )}
    </>
  );
};

export const WorkflowTransitions: FunctionComponent<WorkflowTransitionsProps> = ({ data, entityType = 'DraftWorkspace' }) => {
  const draft = useFragment<WorkflowStatus_data$key>(workflowStatusFragment, data);
  return (
    <WorkflowTransitionsView
      key={draft.id}
      entityId={draft.id}
      entityNavigationId={draft.entity_id}
      draftId={draft.id}
      processingCount={draft.processingCount}
      workflowInstance={draft.workflowInstance}
      entityType={entityType}
    />
  );
};

const WorkflowPendingPoll = ({ refresh }: { refresh: () => void }) => {
  useInterval(refresh, FIVE_SECONDS, false);
  return null;
};

export const WorkflowTransitionsForEntity: FunctionComponent<{
  data: WorkflowStatusStixDomainObject_data$key;
  entityType: string;
}> = ({ data, entityType }) => {
  const entity = useFragment<WorkflowStatusStixDomainObject_data$key>(workflowStatusStixDomainObjectFragment, data);
  const environment = useRelayEnvironment();
  const { t_i18n } = useFormatter();
  const { isFeatureEnable } = useHelper();
  const { canEdit } = useGetCurrentUserAccessRight(entity.currentUserAccessRight);
  const enabled = canEdit && isWorkflowUiEnabledForType(entityType, isFeatureEnable) && !!entity.workflowInstance;
  const request = useRef<Subscription | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const [refreshFailed, setRefreshFailed] = useState(false);

  useEffect(() => {
    setRefreshing(false);
    setRefreshFailed(false);
    return () => {
      request.current?.unsubscribe();
      request.current = null;
    };
  }, [environment, entity.id, enabled]);

  const refresh = () => {
    if (!enabled || request.current) return;
    setRefreshing(true);
    setRefreshFailed(false);
    fetchQuery<WorkflowStatusEntityQuery>(environment, workflowStatusEntityQuery, { id: entity.id }, { fetchPolicy: 'network-only' }).subscribe({
      start: (subscription) => {
        request.current = subscription;
      },
      complete: () => {
        request.current = null;
        setRefreshing(false);
      },
      error: (error: Error) => {
        request.current = null;
        setRefreshing(false);
        setRefreshFailed(true);
        relayErrorHandling(error);
      },
    });
  };

  if (!enabled) return null;
  return (
    <>
      {entity.workflowInstance?.pendingStatus === 'pending' && !refreshFailed && <WorkflowPendingPoll refresh={refresh} />}
      {refreshFailed && <Button variant="secondary" onClick={refresh}>{t_i18n('Retry')}</Button>}
      <WorkflowBypassStatus key={`bypass-${entity.id}`} data={data} entityType={entityType} refreshing={refreshing} onCompleted={refresh} />
      <WorkflowTransitionsView
        key={entity.id}
        entityId={entity.id}
        workflowInstance={entity.workflowInstance}
        entityType={entityType}
        refreshing={refreshing}
        onCompleted={refresh}
      />
    </>
  );
};

export default WorkflowTransitions;
