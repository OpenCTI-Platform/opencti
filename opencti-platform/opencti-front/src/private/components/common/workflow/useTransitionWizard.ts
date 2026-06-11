import { useState } from 'react';
import { useMutation } from 'react-relay';
import { useNavigate } from 'react-router-dom';
import { useFormatter } from '../../../../components/i18n';
import useSwitchDraft from '../../drafts/useSwitchDraft';
import useGranted, { KNOWLEDGE_KNUPDATE_KNBYPASSFIELDS } from '../../../../utils/hooks/useGranted';
import { MESSAGING$ } from '../../../../relay/environment';
import { CommentMode } from '../../settings/sub_types/workflow/utils';
import { workflowStatusTriggerMutation, workflowStatusClearMutation } from './workflowStatus.graphql';
import type { workflowStatusTriggerMutation as WorkflowStatusTriggerMutationType } from './__generated__/WorkflowStatusTriggerMutation.graphql';
import type { workflowStatusClearMutation as WorkflowStatusClearMutationType } from './__generated__/WorkflowStatusClearMutation.graphql';

export type WizardStep = 'org-picker' | 'comment' | 'validate';

export interface TransitionWizard {
  event: string;
  actions: readonly string[];
  steps: WizardStep[];
  runtimeParams?: Record<string, unknown>;
  comment?: string;
  requiresShareOrg: boolean;
  requiresUnshareOrg: boolean;
  commentMode?: string;
}

interface UseTransitionWizardArgs {
  entityId: string;
  entityNavigationId: string | null | undefined;
}

export const useTransitionWizard = ({ entityId, entityNavigationId }: UseTransitionWizardArgs) => {
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const { exitDraft } = useSwitchDraft();
  const canBypassMandatoryFields = useGranted([KNOWLEDGE_KNUPDATE_KNBYPASSFIELDS]);

  const [wizard, setWizard] = useState<TransitionWizard | null>(null);
  const [commentValue, setCommentValue] = useState('');

  const [commit, approving] = useMutation<WorkflowStatusTriggerMutationType>(workflowStatusTriggerMutation);
  const [commitClear, clearing] = useMutation<WorkflowStatusClearMutationType>(workflowStatusClearMutation);

  const exitDraftAfterValidation = () => {
    exitDraft({
      onCompleted: () => {
        if (entityNavigationId) {
          navigate(`/dashboard/id/${entityNavigationId}`);
        } else {
          navigate('/dashboard/data/import/draft');
        }
      },
    });
  };

  const fireTransition = (
    eventName: string,
    actions: readonly string[],
    runtimeParams?: Record<string, unknown>,
    comment?: string,
  ) => {
    commit({
      variables: { entityId, eventName, runtimeParams, comment },
      onCompleted: (response) => {
        if (
          response.triggerWorkflowEvent?.success
          && response.triggerWorkflowEvent.executionStatus !== 'pending'
          && actions.includes('validateDraft')
        ) {
          MESSAGING$.notifySuccess(t_i18n('Draft validation in progress'));
          exitDraftAfterValidation();
        } else if (response.triggerWorkflowEvent?.executionStatus === 'pending') {
          MESSAGING$.notifySuccess(t_i18n('Workflow transition started in background'));
        }
      },
    });
  };

  const advance = (patch?: { runtimeParams?: Record<string, unknown>; comment?: string }) => {
    if (!wizard) return;
    const next: TransitionWizard = {
      ...wizard,
      ...(patch?.runtimeParams !== undefined && {
        runtimeParams: { ...wizard.runtimeParams, ...patch.runtimeParams },
      }),
      ...(patch?.comment !== undefined && { comment: patch.comment }),
      steps: wizard.steps.slice(1),
    };
    if (next.steps.length === 0) {
      setWizard(null);
      fireTransition(next.event, next.actions, next.runtimeParams, next.comment);
    } else {
      setWizard(next);
    }
  };

  const handleTransition = (
    eventName: string,
    actions: readonly string[],
    comment?: string | null,
    requiresShareOrg?: boolean | null,
    requiresUnshareOrg?: boolean | null,
  ) => {
    const steps: WizardStep[] = [];
    if (requiresShareOrg || requiresUnshareOrg) steps.push('org-picker');
    if (comment === CommentMode.allowed || comment === CommentMode.required) steps.push('comment');
    if (actions.includes('validateDraft')) steps.push('validate');

    if (steps.length === 0) {
      fireTransition(eventName, actions);
      return;
    }
    setWizard({
      event: eventName,
      actions,
      steps,
      requiresShareOrg: !!requiresShareOrg,
      requiresUnshareOrg: !!requiresUnshareOrg,
      commentMode: comment ?? undefined,
    });
  };

  const handleOrgPickerSubmit = (
    values: { shareOrganizations: Array<{ value: string }>; unshareOrganizations: Array<{ value: string }> },
    { resetForm }: { resetForm: () => void },
  ) => {
    const rp: Record<string, string[]> = {};
    if (wizard?.requiresShareOrg) rp.shareOrganizationIds = values.shareOrganizations.map((o) => o.value);
    if (wizard?.requiresUnshareOrg) rp.unshareOrganizationIds = values.unshareOrganizations.map((o) => o.value);
    resetForm();
    advance({ runtimeParams: rp });
  };

  const handleConfirmComment = () => {
    advance({ comment: commentValue.trim() || undefined });
    setCommentValue('');
  };

  const handleValidateDraft = () => {
    advance();
  };

  const handleClear = () => {
    commitClear({
      variables: { entityId },
      onCompleted: () => {
        MESSAGING$.notifySuccess(t_i18n('Pending workflow state cleared'));
      },
    });
  };

  const notifyBackgroundTransitionComplete = () => {
    MESSAGING$.notifySuccess(t_i18n('Draft validated successfully'));
    exitDraftAfterValidation();
  };

  return {
    wizard,
    setWizard,
    commentValue,
    setCommentValue,
    currentStep: wizard?.steps[0] ?? null,
    canBypassMandatoryFields,
    approving,
    clearing,
    handleTransition,
    handleOrgPickerSubmit,
    handleConfirmComment,
    handleValidateDraft,
    handleClear,
    notifyBackgroundTransitionComplete,
  };
};
