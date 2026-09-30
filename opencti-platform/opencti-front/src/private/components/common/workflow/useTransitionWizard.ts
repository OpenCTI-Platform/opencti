import { useRef, useState } from 'react';
import { useMutation } from 'react-relay';
import { useNavigate } from 'react-router';
import { useFormatter } from '../../../../components/i18n';
import useSwitchDraft from '../../drafts/useSwitchDraft';
import useGranted, { KNOWLEDGE_KNUPDATE_KNBYPASSFIELDS } from '../../../../utils/hooks/useGranted';
import { MESSAGING$, relayErrorHandling } from '../../../../relay/environment';
import { CommentMode } from '../../settings/sub_types/workflow/utils';
import { workflowStatusTriggerMutation, workflowStatusClearMutation } from './WorkflowStatus.graphql';
import type { WorkflowStatusTriggerMutation as WorkflowStatusTriggerMutationType } from './__generated__/WorkflowStatusTriggerMutation.graphql';
import type { WorkflowStatusClearMutation as WorkflowStatusClearMutationType } from './__generated__/WorkflowStatusClearMutation.graphql';

const DRAFT_COMMENT_SEEN_PREFIX = 'opencti-draft-comment-seen-';

export interface TransitionWizard {
  event: string;
  actions: readonly string[];
  requiresValidation: boolean;
  requiresShareOrg: boolean;
  requiresUnshareOrg: boolean;
  commentMode?: string;
}

export interface TransitionFormValues {
  comment: string;
  shareOrganizations: Array<{ value: string; label?: string }>;
  unshareOrganizations: Array<{ value: string; label?: string }>;
}

interface UseTransitionWizardArgs {
  entityId: string;
  entityNavigationId?: string | null;
  draftId?: string;
  isPending?: boolean;
  onCompleted?: () => void;
}

export const useTransitionWizard = ({ entityId, entityNavigationId, draftId, isPending = false, onCompleted }: UseTransitionWizardArgs) => {
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const { exitDraft } = useSwitchDraft();
  const canBypassMandatoryFields = useGranted([KNOWLEDGE_KNUPDATE_KNBYPASSFIELDS]);

  const [wizard, setWizard] = useState<TransitionWizard | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const inFlight = useRef(false);

  const [commit, approving] = useMutation<WorkflowStatusTriggerMutationType>(workflowStatusTriggerMutation);
  const [commitClear, clearing] = useMutation<WorkflowStatusClearMutationType>(workflowStatusClearMutation);

  const exitDraftAfterValidation = () => {
    if (!draftId) return;
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
  ): Promise<void> => {
    if (inFlight.current || approving || clearing || isPending) return Promise.resolve();
    inFlight.current = true;
    setSubmitting(true);
    return new Promise((resolve) => {
      const finish = () => {
        inFlight.current = false;
        setSubmitting(false);
        resolve();
      };
      commit({
        variables: { entityId, eventName, runtimeParams, comment },
        onCompleted: (response) => {
          finish();
          const result = response.triggerWorkflowEvent;
          if (!result?.success) {
            MESSAGING$.notifyError(result?.reason || t_i18n('An error has occurred'));
            return;
          }
          setWizard(null);
          onCompleted?.();
          const newTimestamp = result.instance?.lastHistoryEntry?.timestamp;
          if (newTimestamp && draftId) {
            window.localStorage.setItem(`${DRAFT_COMMENT_SEEN_PREFIX}${draftId}`, newTimestamp);
          }
          if (result.executionStatus === 'pending') {
            MESSAGING$.notifySuccess(t_i18n('Workflow transition started in background'));
          } else if (draftId && actions.includes('validateDraft')) {
            MESSAGING$.notifySuccess(t_i18n('Draft validation in progress'));
            exitDraftAfterValidation();
          }
        },
        onError: (error) => {
          finish();
          relayErrorHandling(error);
        },
      });
    });
  };

  const handleTransition = (
    eventName: string,
    actions: readonly string[],
    comment?: string | null,
    requiresShareOrg?: boolean | null,
    requiresUnshareOrg?: boolean | null,
  ) => {
    if (inFlight.current || approving || clearing || isPending) return;
    const requiresValidation = !!draftId && actions.includes('validateDraft');
    const hasComment = comment === CommentMode.allowed || comment === CommentMode.required;
    if (!requiresShareOrg && !requiresUnshareOrg && !hasComment && !requiresValidation) {
      fireTransition(eventName, actions);
      return;
    }
    setWizard({
      event: eventName,
      actions,
      requiresValidation,
      requiresShareOrg: !!requiresShareOrg,
      requiresUnshareOrg: !!requiresUnshareOrg,
      commentMode: comment ?? undefined,
    });
  };

  const handleApplyWizard = (values: TransitionFormValues): Promise<void> => {
    if (!wizard) return Promise.resolve();
    const runtimeParams: Record<string, string[]> = {};
    if (wizard.requiresShareOrg) runtimeParams.shareOrganizationIds = values.shareOrganizations.map((organization) => organization.value);
    if (wizard.requiresUnshareOrg) runtimeParams.unshareOrganizationIds = values.unshareOrganizations.map((organization) => organization.value);
    return fireTransition(wizard.event, wizard.actions, runtimeParams, values.comment.trim() || undefined);
  };

  const handleClear = () => {
    if (inFlight.current || approving || clearing) return;
    commitClear({
      variables: { entityId },
      onCompleted: () => {
        onCompleted?.();
        MESSAGING$.notifySuccess(t_i18n('Pending workflow state cleared'));
      },
      onError: relayErrorHandling,
    });
  };

  const notifyBackgroundTransitionComplete = () => {
    if (!draftId) return;
    MESSAGING$.notifySuccess(t_i18n('Draft validated successfully'));
    exitDraftAfterValidation();
  };

  return {
    wizard,
    setWizard,
    canBypassMandatoryFields,
    approving: approving || submitting,
    clearing,
    handleTransition,
    handleApplyWizard,
    handleClear,
    notifyBackgroundTransitionComplete,
  };
};
