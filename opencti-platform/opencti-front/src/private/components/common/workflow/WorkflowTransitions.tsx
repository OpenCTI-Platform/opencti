import React, { FunctionComponent, useEffect, useRef, useState } from 'react';
import { fetchQuery, useFragment, useRelayEnvironment } from 'react-relay';
import type { Subscription } from 'relay-runtime';
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogTitle,
  Icon,
  Menu,
  MenuContent,
  MenuItem,
  MenuTrigger,
  Text,
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from '@filigran/design-system';
import { Alert, AlertTitle, Box, CircularProgress } from '@mui/material';
import { ArrowDropDownOutlined, ArrowDropUpOutlined, ErrorOutline, LockOpenOutlined } from '@mui/icons-material';
import { Field, Form, Formik } from 'formik';
import * as Yup from 'yup';
import ObjectOrganizationField from '../../common/form/ObjectOrganizationField';
import { WorkflowStatus_data$data, WorkflowStatus_data$key } from './__generated__/WorkflowStatus_data.graphql';
import { useFormatter } from '../../../../components/i18n';
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
import WorkflowBypassStatus, { ItemStatusWorkflow } from './WorkflowBypassStatus';
import Button from '@common/button/Button';

const COMMENT_FIELD_ID = 'workflow-transition-comment';

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
          <Text as="span" variant="content-compact" className="whitespace-nowrap">
            {pendingTransition?.event}
          </Text>
          {totalExpected > 0 && (
            <Text as="span" variant="content-compact" className="whitespace-nowrap text-default-secondary">
              {totalProcessed} / {totalExpected}
            </Text>
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
          <Tooltip>
            <TooltipTrigger asChild>
              <ErrorOutline color="error" fontSize="small" />
            </TooltipTrigger>
            <TooltipContent>{workflowInstance.pendingError ?? t_i18n('One or more async workflow actions failed')}</TooltipContent>
          </Tooltip>
          <Text as="span" variant="content-compact" style={{ color: 'var(--text-input-error)' }}>
            {t_i18n('Transition failed')}
          </Text>
          {isBypass && (
            <Tooltip>
              <TooltipTrigger asChild>
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
              </TooltipTrigger>
              <TooltipContent>{t_i18n('Force-unlock this transition (admin only). The background task will be orphaned.')}</TooltipContent>
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
            // Radix gives every DialogDescription the same id, so the validation prompt uses it only when no comment prompt precedes it.
            const showComment = wizard.commentMode === CommentMode.allowed || wizard.commentMode === CommentMode.required;
            const targetStatus = workflowInstance.allowedTransitions.find((transition) => transition.event === wizard.event)?.toStatus;
            return (
              <Dialog
                open
                onOpenChange={(open) => {
                  if (!open && !disabled) setWizard(null);
                }}
              >
                <DialogContent
                  // Radix focuses the first focusable element on open, which is the
                  // close button: when there is a comment to write (sometimes
                  // mandatory, the only action of this step), it gets the focus.
                  // TextareaField does not forward a ref, so it is found by id.
                  onOpenAutoFocus={(event) => {
                    const commentField = document.getElementById(COMMENT_FIELD_ID);
                    if (commentField) {
                      event.preventDefault();
                      commentField.focus();
                    }
                  }}
                >
                  <DialogTitle className="flex flex-col gap-6">
                    <Text variant="title-md">{wizard.event}</Text>

                    {targetStatus && (
                      <div className="flex items-center gap-1">
                        <Text as="span" variant="content-compact-medium">{t_i18n('Transitioning to')}</Text>
                        <ItemStatusWorkflow status={targetStatus} />
                      </div>
                    )}
                  </DialogTitle>
                  <Form noValidate className="flex flex-col gap-6 min-h-0">
                    <DialogBody style={{ margin: 'calc(var(--spacing) * -1)', padding: 'var(--spacing)' }}>
                      <Box className="flex flex-col gap-6">
                        {showComment && (
                          <div className="flex flex-col gap-4">
                            <DialogDescription className="flex flex-col gap-2">
                              <Text variant="title-sm">{t_i18n('Add a comment')}</Text>
                              <Text variant="content-compact">
                                {wizard.commentMode === CommentMode.required
                                  ? t_i18n('A comment is required before changing the status.')
                                  : t_i18n('You can optionally add a comment before changing the status.')}
                              </Text>
                            </DialogDescription>
                            <Field
                              component={TextareaField}
                              id={COMMENT_FIELD_ID}
                              name="comment"
                              label={t_i18n('Comment')}
                              required={wizard.commentMode === CommentMode.required && !canBypassMandatoryFields}
                              disabled={disabled}
                              rows={3}
                              maxLength={COMMENT_MAX_LENGTH}
                              helperText={`${values.comment.length} / ${COMMENT_MAX_LENGTH}`}
                            />
                          </div>
                        )}
                        {wizard.requiresShareOrg && (
                          <div className="flex flex-col gap-4">
                            <div className="flex items-center gap-2">
                              <Icon name="triangle-alert" size={16} className="text-icon-warning" aria-hidden />
                              <Text variant="title-sm">{t_i18n('Share with organizations')}</Text>
                            </div>
                            <ObjectOrganizationField
                              name="shareOrganizations"
                              label={t_i18n('Organizations')}
                              multiple={true}
                              disabled={disabled}
                              style={{ width: '100%' }}
                              alert={false}
                            />
                          </div>
                        )}
                        {wizard.requiresUnshareOrg && (
                          <div className="flex flex-col gap-4">
                            <div className="flex items-center gap-2">
                              <Icon name="triangle-alert" size={16} className="text-icon-warning" aria-hidden />
                              <Text variant="title-sm">{t_i18n('Unshare from organizations')}</Text>
                            </div>
                            <ObjectOrganizationField
                              name="unshareOrganizations"
                              label={t_i18n('Organizations')}
                              multiple={true}
                              disabled={disabled}
                              style={{ width: '100%' }}
                              alert={false}
                            />
                          </div>
                        )}
                        {wizard.requiresValidation && (
                          <>
                            {showComment ? (
                              <Text variant="content-base">{t_i18n('Do you want to approve this draft and send it to ingestion?')}</Text>
                            ) : (
                              <DialogDescription>{t_i18n('Do you want to approve this draft and send it to ingestion?')}</DialogDescription>
                            )}
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
                    </DialogBody>
                    <DialogFooter>
                      <Button variant="secondary" onClick={() => setWizard(null)} disabled={disabled}>
                        {t_i18n('Cancel')}
                      </Button>
                      <Button type="submit" disabled={disabled || !isValid || !!missingComment || values.comment.length > COMMENT_MAX_LENGTH}>
                        {wizard.requiresValidation ? t_i18n('Approve') : t_i18n('Confirm')}
                      </Button>
                    </DialogFooter>
                  </Form>
                </DialogContent>
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
