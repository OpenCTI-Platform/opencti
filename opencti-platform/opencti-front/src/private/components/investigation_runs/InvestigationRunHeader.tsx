/*
Copyright (c) 2021-2025 Filigran SAS

This file is part of the OpenCTI Enterprise Edition ("EE") and is
licensed under the OpenCTI Enterprise Edition License (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://github.com/OpenCTI-Platform/opencti/blob/master/LICENSE

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*/

import React, { useState } from 'react';
import { graphql } from 'react-relay';
import { Link, useNavigate } from 'react-router';
import Stack from '@mui/material/Stack';
import Typography from '@mui/material/Typography';
import DialogActions from '@mui/material/DialogActions';
import { MoreVertOutlined, OpenInNewOutlined, PlayArrowOutlined, ReplayOutlined } from '@mui/icons-material';
import { IconButton, Menu, MenuContent, MenuItem, MenuSeparator, MenuTrigger, ProgressBar, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import Card from '@common/card/Card';
import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import { useFormatter } from '../../../components/i18n';
import useGranted, { KNOWLEDGE_KNUPDATE, KNOWLEDGE_KNUPDATE_KNDELETE, SETTINGS_SETCUSTOMIZATION } from '../../../utils/hooks/useGranted';
import useApiMutation from '../../../utils/hooks/useApiMutation';
import InvestigationRunStatusChip from './InvestigationRunStatusChip';
import { NextAction, type StepActionHandlers } from './InvestigationRunStepNextAction';
import {
  budgetPercent,
  buildGoalPlanView,
  engineReasonLabel,
  investigationGraphPath,
  isDraftValidationFailure,
  isEngineRunOver,
  isRunActive,
  MEMBER_RESTRICTED_CODE,
  reportMutationOutcome,
  SOURCE_INACCESSIBLE_CODE,
} from './investigationRunUtils';
import { CASE_AUTOPILOT_DOCS_URL, formatDuration, POLICIES_PATH, runReasonNext, runStatusSentence } from './investigationRunOutcomes';
import { draftChangeCount } from './investigationRunDraftChanges';
import type { InvestigationRunView_run$data } from './__generated__/InvestigationRunView_run.graphql';
import { InvestigationRunHeaderCancelMutation } from './__generated__/InvestigationRunHeaderCancelMutation.graphql';
import { InvestigationRunHeaderDeleteMutation } from './__generated__/InvestigationRunHeaderDeleteMutation.graphql';

type Run = InvestigationRunView_run$data;

const investigationRunHeaderCancelMutation = graphql`
  mutation InvestigationRunHeaderCancelMutation($id: ID!) {
    investigationRunCancel(id: $id) {
      id
      ...InvestigationRunView_run
    }
  }
`;

const investigationRunHeaderDeleteMutation = graphql`
  mutation InvestigationRunHeaderDeleteMutation($id: ID!) {
    investigationRunDelete(id: $id)
  }
`;

const RUN_TRIGGER_SENTENCES: Record<string, string> = {
  manual: 'Started manually by {user} - {time}',
  playbook: 'Started by a playbook as {user} - {time}',
  case_rfi_creation: 'Started when the request for information was created - {time}',
};

interface InvestigationRunHeaderProps {
  run: Run;
  handlers: StepActionHandlers;
  onOpenReport: () => void;
  onGiveFeedback: () => void;
  launching: boolean;
  continuing: boolean;
  onDeleted?: () => void;
}

/**
 * The status header of an investigation: its state in one line, who acts,
 * its iteration budget, the primary action of the state, at most two
 * secondary actions and the rest in "More actions".
 */
const InvestigationRunHeader = ({ run, handlers, onOpenReport, onGiveFeedback, launching, continuing, onDeleted }: InvestigationRunHeaderProps) => {
  const { t_i18n, n, rd, fldt } = useFormatter();
  const navigate = useNavigate();
  const [confirm, setConfirm] = useState<'cancel' | 'delete' | null>(null);
  const [commitCancel, cancelling] = useApiMutation<InvestigationRunHeaderCancelMutation>(investigationRunHeaderCancelMutation);
  const [commitDelete, deleting] = useApiMutation<InvestigationRunHeaderDeleteMutation>(investigationRunHeaderDeleteMutation);
  const canCancel = useGranted([KNOWLEDGE_KNUPDATE]);
  const canDelete = useGranted([KNOWLEDGE_KNUPDATE_KNDELETE]);
  const canCustomize = useGranted([SETTINGS_SETCUSTOMIZATION]);
  const { onRunAgain, onContinue } = handlers;
  const active = isRunActive(run.run_status);
  // The approved draft is being written into the knowledge: that work cannot be recalled.
  const validating = active && run.run_phase === 'validating';
  const pending = run.approvals.filter((approval) => approval.status === 'pending');
  const draftGate = pending.find((approval) => approval.kind === 'draft_validation');
  const draftOpen = !!run.draft && run.draft.draft_status !== 'validated';
  const draftChanges = draftGate ? draftChangeCount(run.draft?.objectsCount) : null;
  const view = buildGoalPlanView(run.goal_plan, run.steps, isEngineRunOver(run), !!run.report);
  const currentIndex = view.actions.findIndex((action) => action.status === 'active');
  const nextIndex = currentIndex >= 0 ? currentIndex : view.actions.findIndex((action) => action.status === 'pending');
  const engineReason = engineReasonLabel(run.end_reason_code);
  const reasonText = engineReason ? t_i18n(engineReason) : (run.status_reason ? t_i18n(run.status_reason) : null);
  const reasonNext = runReasonNext(run.status_reason, run.end_reason_code);
  const { budget } = run;
  const iterationsSpent = budget.max_iterations > 0 && budget.used_iterations >= budget.max_iterations;
  // The error tone is kept for failures: a run that used its budget and concluded did not fail.
  const budgetFailed = iterationsSpent && run.run_status === 'failed' && !isDraftValidationFailure(run.end_reason_code);
  const usedMinutes = Math.round(budget.used_minutes * 100) / 100;
  const sentence = run.run_status === 'failed' && reasonText ? reasonText : runStatusSentence({
    run_status: run.run_status,
    run_phase: run.run_phase,
    draft_status: run.draft?.draft_status,
    pendingDraftChanges: draftChanges,
    pendingRequests: pending.length,
    currentStep: nextIndex >= 0 ? { index: nextIndex + 1, total: view.actions.length, label: view.actions[nextIndex].label } : null,
    stepsFound: view.actions.filter((action) => action.status === 'completed').length,
    stepsTotal: view.actions.length,
  }, t_i18n);
  const reportPath = run.report_id && !draftOpen ? `/dashboard/analyses/reports/${run.report_id}` : null;
  const continueButton = (priority: 'primary' | 'secondary') => (
    <Button key="continue" size="small" variant={priority === 'primary' ? undefined : 'secondary'} intent="ai" startIcon={<PlayArrowOutlined fontSize="small" />} disabled={continuing} onClick={onContinue} data-testid="investigation-run-continue">
      {t_i18n('Continue the investigation')}
    </Button>
  );
  const continueAsPrimary = !!onContinue && iterationsSpent;

  // The primary action follows the state; at most two secondary actions stay visible.
  let primary: React.ReactNode = null;
  const secondary: React.ReactNode[] = [];
  const reviewButton = (priority: 'primary' | 'secondary') => (
    <Button key="review" size="small" variant={priority} onClick={handlers.onReviewApprovals} data-testid="investigation-run-review">
      {draftChanges !== null && draftChanges > 0
        ? t_i18n('Review {count} changes', { values: { count: n(draftChanges) } })
        : t_i18n('Review {count} requests', { values: { count: n(pending.length) } })}
    </Button>
  );
  if (run.run_status === 'awaiting_approval' && pending.length > 0) {
    // Reviewing what waits is the primary action; continuing a run that spent
    // its iterations stays one click away, as a secondary action.
    primary = reviewButton('primary');
    if (continueAsPrimary) secondary.push(continueButton('secondary'));
    if (draftOpen && run.draft) {
      secondary.push(
        <Button key="draft" size="small" variant="secondary" component={Link} to={`/dashboard/data/import/draft/${run.draft.id}`} startIcon={<OpenInNewOutlined fontSize="small" />}>
          {t_i18n('Open the draft')}
        </Button>,
      );
    }
  } else if (run.run_status === 'completed') {
    primary = reportPath
      ? <Button size="small" component={Link} to={reportPath} data-testid="investigation-run-open-report">{t_i18n('Open the report')}</Button>
      : <Button size="small" onClick={onOpenReport} data-testid="investigation-run-open-report">{t_i18n('Open the report')}</Button>;
    if (onRunAgain) {
      secondary.push(<Button key="again" size="small" variant="secondary" intent="ai" onClick={onRunAgain} disabled={launching} data-testid="investigation-run-again">{t_i18n('Run again')}</Button>);
    }
    if (run.hypotheses.length > 0 || run.recommendations.length > 0) {
      secondary.push(<Button key="feedback" size="small" variant="secondary" onClick={onGiveFeedback}>{t_i18n('Give feedback')}</Button>);
    }
  } else if (run.run_status === 'failed' || run.run_status === 'cancelled') {
    if (onRunAgain) {
      primary = (
        <Button size="small" intent="ai" startIcon={<ReplayOutlined fontSize="small" />} onClick={onRunAgain} disabled={launching} data-testid="investigation-run-again">
          {run.run_status === 'failed' ? t_i18n('Retry') : t_i18n('Run again')}
        </Button>
      );
    }
    // Policies cannot lift a member restriction or a lost access: the sentence says what can.
    if (run.run_status === 'failed' && canCustomize && run.end_reason_code !== MEMBER_RESTRICTED_CODE && run.end_reason_code !== SOURCE_INACCESSIBLE_CODE) {
      secondary.push(<Button key="policies" size="small" variant="secondary" component={Link} to={POLICIES_PATH}>{t_i18n('Open the investigation policies')}</Button>);
    }
  } else if (active && run.workspace_id) {
    secondary.push(
      <Button key="graph" size="small" variant="secondary" component={Link} to={investigationGraphPath(run.workspace_id)}>{t_i18n('Open the investigation graph')}</Button>,
    );
  }
  const graphInSecondary = secondary.some((item) => React.isValidElement(item) && item.key === 'graph');
  const menuItems: React.ReactNode[] = [];
  if (run.workspace_id && !graphInSecondary) {
    const workspaceId = run.workspace_id;
    menuItems.push(<MenuItem key="graph" onSelect={() => navigate(investigationGraphPath(workspaceId))}>{t_i18n('Open the investigation graph')}</MenuItem>);
  }
  if (onContinue && !continueAsPrimary) {
    menuItems.push(<MenuItem key="continue" onSelect={onContinue} disabled={continuing}>{t_i18n('Continue the investigation')}</MenuItem>);
  }
  if (draftOpen && run.draft && run.run_status !== 'awaiting_approval') {
    const draftId = run.draft.id;
    menuItems.push(<MenuItem key="draft" onSelect={() => navigate(`/dashboard/data/import/draft/${draftId}`)}>{t_i18n('Open the draft')}</MenuItem>);
  }
  menuItems.push(
    <MenuItem key="docs" onSelect={() => window.open(CASE_AUTOPILOT_DOCS_URL, '_blank', 'noopener,noreferrer')}>{t_i18n('Read the documentation')}</MenuItem>,
  );
  const destructive: React.ReactNode[] = [];
  if (active && canCancel && !validating) {
    destructive.push(<MenuItem key="cancel" onSelect={() => setConfirm('cancel')} data-testid="investigation-run-cancel">{t_i18n('Cancel the investigation')}</MenuItem>);
  }
  if (!active && canDelete) {
    destructive.push(<MenuItem key="delete" onSelect={() => setConfirm('delete')} data-testid="investigation-run-delete">{t_i18n('Delete')}</MenuItem>);
  }
  const subjectName = run.subject?.representative.main ?? run.case?.name;
  const triggerTemplate = RUN_TRIGGER_SENTENCES[run.run_trigger] ?? RUN_TRIGGER_SENTENCES.manual;
  return (
    <Card
      title={t_i18n('Investigation')}
      action={(
        <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap>
          {primary}
          {secondary.slice(0, 2)}
          <Menu>
            <MenuTrigger asChild>
              <IconButton priority="tertiary" size="sm" aria-label={t_i18n('More actions on the investigation')} icon={<MoreVertOutlined fontSize="small" />} data-testid="investigation-run-more" />
            </MenuTrigger>
            <MenuContent align="end">
              {menuItems}
              {destructive.length > 0 && <MenuSeparator />}
              {destructive}
            </MenuContent>
          </Menu>
        </Stack>
      )}
    >
      <Stack spacing={2} data-testid="investigation-run-header">
        <Stack spacing={0.5}>
          <Stack direction="row" spacing={1.5} alignItems="center" flexWrap="wrap" useFlexGap>
            <InvestigationRunStatusChip status={run.run_status} />
            <Typography variant="body1" aria-live="polite" data-testid="investigation-run-sentence">{sentence}</Typography>
          </Stack>
          {validating && (
            <Typography variant="body2" color="text.secondary" data-testid="investigation-run-not-cancellable">
              {t_i18n('It can no longer be cancelled: the investigation ends once every approved change is written.')}
            </Typography>
          )}
          <Tooltip>
            <TooltipTrigger asChild>
              <Typography variant="body2" color="text.secondary" tabIndex={0} sx={{ alignSelf: 'flex-start' }}>
                {t_i18n(triggerTemplate, { values: { user: run.runAs?.name ?? t_i18n('an analyst'), time: rd(run.created_at) } })}
              </Typography>
            </TooltipTrigger>
            <TooltipContent>{fldt(run.created_at)}</TooltipContent>
          </Tooltip>
          {!active && reasonNext && (
            <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap data-testid="investigation-run-reason">
              {run.run_status !== 'failed' && reasonText && <Typography variant="body2" color="text.secondary">{reasonText}</Typography>}
              <NextAction next={reasonNext} handlers={handlers} />
            </Stack>
          )}
          {!active && !reasonNext && reasonText && run.run_status !== 'failed' && (
            <Typography variant="body2" color="text.secondary" data-testid="investigation-run-reason">{reasonText}</Typography>
          )}
        </Stack>
        <Stack spacing={0.5}>
          <Typography variant="body2" id={`investigation-iterations-${run.id}`} color={budgetFailed ? 'error.main' : undefined}>
            {iterationsSpent
              ? t_i18n('Budget spent - {used} of {max} iterations', { values: { used: n(budget.used_iterations), max: n(budget.max_iterations) } })
              : t_i18n('{used} of {max} iterations', { values: { used: n(budget.used_iterations), max: n(budget.max_iterations) } })}
          </Typography>
          <ProgressBar
            aria-labelledby={`investigation-iterations-${run.id}`}
            value={budgetPercent(budget.used_iterations, budget.max_iterations)}
            tone={budgetFailed ? 'error' : 'default'}
          />
          <Typography variant="caption" color="text.secondary">
            {t_i18n('{usedJobs} of {maxJobs} enrichment jobs - {usedTime} of {maxTime}', {
              values: {
                usedJobs: n(budget.used_enrichment_jobs),
                maxJobs: n(budget.max_enrichment_jobs),
                usedTime: formatDuration(usedMinutes * 60000, t_i18n),
                maxTime: formatDuration(budget.max_minutes * 60000, t_i18n),
              },
            })}
          </Typography>
        </Stack>
      </Stack>
      <Dialog
        open={confirm !== null}
        onClose={() => setConfirm(null)}
        title={confirm === 'cancel' ? t_i18n('Cancel the investigation') : t_i18n('Delete the investigation')}
        size="small"
      >
        <span>
          {confirm === 'cancel'
            ? t_i18n('Case Autopilot stops the investigation of {name} now. What it already wrote stays in its draft.', { values: { name: subjectName ?? t_i18n('this case') } })
            : t_i18n('The investigation of {name}, its goal plan, its evidence and its analyst feedback are deleted. The knowledge it wrote stays.', { values: { name: subjectName ?? t_i18n('this case') } })}
        </span>
        <DialogActions>
          <Button variant="secondary" onClick={() => setConfirm(null)} disabled={cancelling || deleting}>{t_i18n('Keep it')}</Button>
          <Button
            intent="destructive"
            disabled={cancelling || deleting}
            data-testid="investigation-run-confirm"
            onClick={() => {
              if (confirm === 'cancel') {
                commitCancel({
                  variables: { id: run.id },
                  onCompleted: (_, errors) => {
                    setConfirm(null);
                    reportMutationOutcome(errors, t_i18n('The investigation was cancelled'));
                  },
                });
              } else {
                commitDelete({
                  variables: { id: run.id },
                  onCompleted: (_, errors) => {
                    setConfirm(null);
                    if (reportMutationOutcome(errors, t_i18n('The investigation was deleted'))) onDeleted?.();
                  },
                });
              }
            }}
          >
            {confirm === 'cancel' ? t_i18n('Cancel the investigation') : t_i18n('Delete')}
          </Button>
        </DialogActions>
      </Dialog>
    </Card>
  );
};

export default InvestigationRunHeader;
