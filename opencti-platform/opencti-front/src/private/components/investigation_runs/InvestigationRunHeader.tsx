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

import React, { Suspense, useState } from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import { Link, useNavigate } from 'react-router';
import Box from '@mui/material/Box';
import Stack from '@mui/material/Stack';
import Typography from '@mui/material/Typography';
import DialogActions from '@mui/material/DialogActions';
import { MoreVertOutlined, OpenInNewOutlined, PlayArrowOutlined, ReplayOutlined } from '@mui/icons-material';
import { IconButton, Menu, MenuContent, MenuItem, MenuSeparator, MenuTrigger, ProgressBar, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import Card from '@common/card/Card';
import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import ItemIcon from '../../../components/ItemIcon';
import { useFormatter } from '../../../components/i18n';
import useGranted, { KNOWLEDGE_KNENRICHMENT, KNOWLEDGE_KNUPDATE, KNOWLEDGE_KNUPDATE_KNDELETE, SETTINGS_SETCUSTOMIZATION } from '../../../utils/hooks/useGranted';
import useApiMutation from '../../../utils/hooks/useApiMutation';
import InvestigationRunStatusChip from './InvestigationRunStatusChip';
import { NextAction, type StepActionHandlers } from './InvestigationRunStepNextAction';
import {
  budgetPercent,
  buildGoalPlanView,
  DEFAULT_PACK,
  elementPath,
  engineReasonLabel,
  formatProbability,
  investigationGraphPath,
  isEngineRunOver,
  isRunActive,
  reportMutationOutcome,
} from './investigationRunUtils';
import { CASE_AUTOPILOT_DOCS_URL, elapsedMs, formatDuration, POLICIES_PATH, runReasonNext, runStatusSentence } from './investigationRunOutcomes';
import type { InvestigationRunView_run$data } from './__generated__/InvestigationRunView_run.graphql';
import { InvestigationRunHeaderCancelMutation } from './__generated__/InvestigationRunHeaderCancelMutation.graphql';
import { InvestigationRunHeaderDeleteMutation } from './__generated__/InvestigationRunHeaderDeleteMutation.graphql';
import { InvestigationRunHeaderContinueMutation } from './__generated__/InvestigationRunHeaderContinueMutation.graphql';
import { InvestigationRunHeaderPacksQuery } from './__generated__/InvestigationRunHeaderPacksQuery.graphql';

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

const investigationRunHeaderContinueMutation = graphql`
  mutation InvestigationRunHeaderContinueMutation($id: ID!) {
    investigationRunContinue(id: $id) {
      id
      ...InvestigationRunView_run
    }
  }
`;

const investigationRunHeaderPacksQuery = graphql`
  query InvestigationRunHeaderPacksQuery {
    investigationPacks {
      packs {
        slug
        label
      }
    }
  }
`;

const RUN_TRIGGER_SENTENCES: Record<string, string> = {
  manual: 'Started manually by {user} {time}',
  playbook: 'Started by a playbook as {user} {time}',
  case_rfi_creation: 'Started on the creation of the request for information, as {user} {time}',
};

const BuiltPackName = ({ slug }: { slug: string }) => {
  const { t_i18n } = useFormatter();
  const data = useLazyLoadQuery<InvestigationRunHeaderPacksQuery>(investigationRunHeaderPacksQuery, {}, { fetchPolicy: 'store-or-network' });
  const pack = data.investigationPacks?.packs.find((item) => item.slug === slug);
  return <>{pack?.label ?? t_i18n('Custom pack')}</>;
};

const PackName = ({ slug }: { slug: string | null | undefined }) => {
  const { t_i18n } = useFormatter();
  if (!slug || slug === DEFAULT_PACK) return <>{t_i18n('OpenCTI case investigation')}</>;
  return <Suspense fallback={t_i18n('Custom pack')}><BuiltPackName slug={slug} /></Suspense>;
};

const MetaItem = ({ label, children }: { label: string; children: React.ReactNode }) => (
  <Stack spacing={0.25} sx={{ minWidth: 0 }}>
    <Typography variant="caption" color="text.secondary">{label}</Typography>
    <Box sx={{ typography: 'body2', minWidth: 0, overflowWrap: 'anywhere' }}>{children}</Box>
  </Stack>
);

const EntityLink = ({ entity, current }: { entity: { id: string; entity_type: string; name: string }; current: boolean }) => (
  <Stack direction="row" spacing={0.75} alignItems="center" sx={{ minWidth: 0 }}>
    <ItemIcon type={entity.entity_type} size="small" />
    {current ? <span>{entity.name}</span> : <Link to={elementPath(entity.id)}>{entity.name}</Link>}
  </Stack>
);

const TimeWithTooltip = ({ date, children }: { date: string; children: React.ReactNode }) => {
  const { fldt } = useFormatter();
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span tabIndex={0}>{children}</span>
      </TooltipTrigger>
      <TooltipContent>{fldt(date)}</TooltipContent>
    </Tooltip>
  );
};

interface InvestigationRunHeaderProps {
  run: Run;
  currentEntityId?: string;
  handlers: StepActionHandlers;
  onOpenReport: () => void;
  onGiveFeedback: () => void;
  launching: boolean;
  onDeleted?: () => void;
}

/**
 * The status header of an investigation: its state, one sentence saying who
 * acts, its progress and budget, the primary action of the state and the
 * rest in "More actions".
 */
const InvestigationRunHeader = ({ run, currentEntityId, handlers, onOpenReport, onGiveFeedback, launching, onDeleted }: InvestigationRunHeaderProps) => {
  const { t_i18n, n, rd } = useFormatter();
  const navigate = useNavigate();
  const [confirm, setConfirm] = useState<'cancel' | 'delete' | null>(null);
  const [commitCancel, cancelling] = useApiMutation<InvestigationRunHeaderCancelMutation>(investigationRunHeaderCancelMutation);
  const [commitDelete, deleting] = useApiMutation<InvestigationRunHeaderDeleteMutation>(investigationRunHeaderDeleteMutation);
  const [commitContinue, continuing] = useApiMutation<InvestigationRunHeaderContinueMutation>(investigationRunHeaderContinueMutation);
  const canLaunch = useGranted([KNOWLEDGE_KNUPDATE, KNOWLEDGE_KNENRICHMENT], true);
  const runAgain = handlers.onRunAgain;
  const canCancel = useGranted([KNOWLEDGE_KNUPDATE]);
  const canDelete = useGranted([KNOWLEDGE_KNUPDATE_KNDELETE]);
  const canCustomize = useGranted([SETTINGS_SETCUSTOMIZATION]);
  const active = isRunActive(run.run_status);
  const pending = run.approvals.filter((approval) => approval.status === 'pending');
  const draftGate = pending.find((approval) => approval.kind === 'draft_validation');
  const draftOpen = !!run.draft && run.draft.draft_status !== 'validated';
  const draftChanges = draftGate ? (run.draft?.objectsCount.totalCount ?? 0) : null;
  const view = buildGoalPlanView(run.goal_plan, run.steps, isEngineRunOver(run));
  const stepsDone = view.actions.filter((action) => !['pending', 'active'].includes(action.status)).length;
  const sentence = runStatusSentence({
    run_status: run.run_status,
    run_phase: run.run_phase,
    draft_status: run.draft?.draft_status,
    pendingDraftChanges: draftChanges,
    pendingRequests: pending.length,
    stepsDone,
    stepsTotal: view.actions.length,
  }, t_i18n);
  const engineReason = engineReasonLabel(run.end_reason_code);
  const reasonText = engineReason ? t_i18n(engineReason) : (run.status_reason ? t_i18n(run.status_reason) : null);
  const reasonNext = runReasonNext(run.status_reason, run.end_reason_code);
  const { budget } = run;
  const usedMinutes = Math.round(budget.used_minutes * 100) / 100;
  const acceptance = run.acceptance;
  const decisions = acceptance.hypotheses_accepted + acceptance.hypotheses_rejected + acceptance.recommendations_accepted + acceptance.recommendations_rejected;
  const sameCase = !!run.case && run.subject?.id === run.case.id;
  const duration = elapsedMs(run.started_at, run.completed_at);
  const continueRun = () => commitContinue({
    variables: { id: run.id },
    onCompleted: (_, errors) => {
      reportMutationOutcome(errors, t_i18n('The investigation continues'));
    },
  });
  const reportPath = run.report_id && !draftOpen ? `/dashboard/analyses/reports/${run.report_id}` : null;

  // The primary action follows the state; at most two secondary actions stay visible.
  let primary: React.ReactNode = null;
  const secondary: React.ReactNode[] = [];
  if (run.run_status === 'awaiting_approval' && pending.length > 0) {
    primary = (
      <Button size="small" onClick={handlers.onReviewApprovals} data-testid="investigation-run-review">
        {draftChanges !== null && draftChanges > 0
          ? t_i18n('Review {count} changes', { values: { count: n(draftChanges) } })
          : t_i18n('Review {count} requests', { values: { count: n(pending.length) } })}
      </Button>
    );
  } else if (run.run_status === 'completed') {
    primary = reportPath
      ? <Button size="small" component={Link} to={reportPath} data-testid="investigation-run-open-report">{t_i18n('Open the report')}</Button>
      : <Button size="small" onClick={onOpenReport} data-testid="investigation-run-open-report">{t_i18n('Open the report')}</Button>;
  } else if ((run.run_status === 'failed' || run.run_status === 'cancelled') && runAgain) {
    primary = (
      <Button size="small" intent="ai" startIcon={<ReplayOutlined fontSize="small" />} onClick={runAgain} disabled={launching} data-testid="investigation-run-again">
        {run.run_status === 'failed' ? t_i18n('Retry') : t_i18n('Run again')}
      </Button>
    );
  }
  if (run.can_continue && canLaunch) {
    secondary.push(
      <Button key="continue" size="small" variant="secondary" intent="ai" startIcon={<PlayArrowOutlined fontSize="small" />} disabled={continuing} onClick={continueRun} data-testid="investigation-run-continue">
        {t_i18n('Continue investigation')}
      </Button>,
    );
  }
  if (draftOpen && run.draft && run.run_status === 'awaiting_approval') {
    secondary.push(
      <Button key="draft" size="small" variant="secondary" component={Link} to={`/dashboard/data/import/draft/${run.draft.id}`} startIcon={<OpenInNewOutlined fontSize="small" />}>
        {t_i18n('Open the draft')}
      </Button>,
    );
  }
  if (run.run_status === 'completed') {
    if (runAgain) {
      secondary.push(
        <Button key="again" size="small" variant="secondary" intent="ai" onClick={runAgain} disabled={launching} data-testid="investigation-run-again">{t_i18n('Run again')}</Button>,
      );
    }
    if (run.hypotheses.length > 0 || run.recommendations.length > 0) {
      secondary.push(<Button key="feedback" size="small" variant="secondary" onClick={onGiveFeedback}>{t_i18n('Give feedback')}</Button>);
    }
  }
  if (run.run_status === 'failed' && canCustomize) {
    secondary.push(<Button key="policies" size="small" variant="secondary" component={Link} to={POLICIES_PATH}>{t_i18n('Open the investigation policies')}</Button>);
  }
  const graphInSecondary = active && !!run.workspace_id && secondary.length < 2;
  if (graphInSecondary && run.workspace_id) {
    secondary.push(
      <Button key="graph" size="small" variant="secondary" component={Link} to={investigationGraphPath(run.workspace_id)}>{t_i18n('Open the investigation graph')}</Button>,
    );
  }
  const visibleSecondary = secondary.slice(0, 2);
  const menuItems: React.ReactNode[] = [];
  if (run.workspace_id && !graphInSecondary) {
    const workspaceId = run.workspace_id;
    menuItems.push(<MenuItem key="graph" onSelect={() => navigate(investigationGraphPath(workspaceId))}>{t_i18n('Open the investigation graph')}</MenuItem>);
  }
  if (draftOpen && run.draft && run.run_status !== 'awaiting_approval') {
    const draftId = run.draft.id;
    menuItems.push(<MenuItem key="draft" onSelect={() => navigate(`/dashboard/data/import/draft/${draftId}`)}>{t_i18n('Open the draft')}</MenuItem>);
  }
  menuItems.push(
    <MenuItem key="docs" onSelect={() => window.open(CASE_AUTOPILOT_DOCS_URL, '_blank', 'noopener,noreferrer')}>{t_i18n('Read the documentation')}</MenuItem>,
  );
  const destructive: React.ReactNode[] = [];
  if (active && canCancel) {
    destructive.push(<MenuItem key="cancel" onSelect={() => setConfirm('cancel')} data-testid="investigation-run-cancel">{t_i18n('Cancel the investigation')}</MenuItem>);
  }
  if (!active && canDelete) {
    destructive.push(<MenuItem key="delete" onSelect={() => setConfirm('delete')} data-testid="investigation-run-delete">{t_i18n('Delete the investigation')}</MenuItem>);
  }
  const triggerTemplate = RUN_TRIGGER_SENTENCES[run.run_trigger] ?? RUN_TRIGGER_SENTENCES.manual;
  const subjectName = run.subject?.representative.main;
  return (
    <Card
      title={t_i18n('Case Autopilot')}
      action={(
        <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap>
          {primary}
          {visibleSecondary}
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
      <Stack spacing={2.5} data-testid="investigation-run-header">
        <Stack spacing={0.75}>
          <Stack direction="row" spacing={1.5} alignItems="center" flexWrap="wrap" useFlexGap>
            <InvestigationRunStatusChip status={run.run_status} />
            <Typography variant="body1" aria-live="polite" data-testid="investigation-run-sentence">{sentence}</Typography>
          </Stack>
          <Typography variant="body2" color="text.secondary">
            <TimeWithTooltip date={run.created_at}>
              {t_i18n(triggerTemplate, { values: { user: run.runAs?.name ?? t_i18n('an analyst'), time: rd(run.created_at) } })}
            </TimeWithTooltip>
          </Typography>
          {reasonText && !active && (
            <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap data-testid="investigation-run-reason">
              <Typography variant="body2" color={run.run_status === 'failed' ? 'error.main' : 'text.secondary'}>{reasonText}</Typography>
              {reasonNext && <NextAction next={reasonNext} handlers={handlers} />}
            </Stack>
          )}
        </Stack>
        <Stack spacing={0.5}>
          <Typography variant="body2" id={`investigation-iterations-${run.id}`}>
            {t_i18n('{used} of {max} iterations', { values: { used: n(budget.used_iterations), max: n(budget.max_iterations) } })}
          </Typography>
          <ProgressBar
            aria-labelledby={`investigation-iterations-${run.id}`}
            value={budgetPercent(budget.used_iterations, budget.max_iterations)}
            tone={budgetPercent(budget.used_iterations, budget.max_iterations) >= 100 ? 'error' : 'default'}
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
        <Box
          sx={{
            display: 'grid',
            gap: 2,
            gridTemplateColumns: { xs: '1fr', sm: 'repeat(2, minmax(0, 1fr))', lg: 'repeat(4, minmax(0, 1fr))' },
          }}
          data-testid="investigation-run-metadata"
        >
          {sameCase && run.case ? (
            <MetaItem label={t_i18n('Case')}>
              <EntityLink entity={run.case} current={run.case.id === currentEntityId} />
            </MetaItem>
          ) : (
            <>
              <MetaItem label={t_i18n('Investigated entity')}>
                {run.subject && subjectName
                  ? <EntityLink entity={{ id: run.subject.id, entity_type: run.subject.entity_type, name: subjectName }} current={run.subject.id === currentEntityId} />
                  : t_i18n('Restricted entity')}
              </MetaItem>
              <MetaItem label={t_i18n('Case')}>
                {run.case
                  ? <EntityLink entity={run.case} current={run.case.id === currentEntityId} />
                  : t_i18n('A new case, in the investigation draft')}
              </MetaItem>
            </>
          )}
          <MetaItem label={t_i18n('Investigation policy')}>
            {run.policy
              ? (canCustomize ? <Link to={POLICIES_PATH}>{run.policy.name}</Link> : run.policy.name)
              : t_i18n('Not recorded')}
          </MetaItem>
          <MetaItem label={t_i18n('Pack')}><PackName slug={run.pack_id} /></MetaItem>
          <MetaItem label={t_i18n('Runs as')}>{run.runAs?.name ?? t_i18n('Not recorded')}</MetaItem>
          <MetaItem label={active ? t_i18n('Running for') : t_i18n('Duration')}>
            {duration !== null ? formatDuration(duration, t_i18n) : t_i18n('Not started yet')}
          </MetaItem>
          {run.completed_at && (
            <MetaItem label={t_i18n('Ended')}>
              <TimeWithTooltip date={run.completed_at}>{rd(run.completed_at)}</TimeWithTooltip>
            </MetaItem>
          )}
          {decisions > 0 && acceptance.rate !== null && acceptance.rate !== undefined && (
            <MetaItem label={t_i18n('Analyst acceptance')}>
              {t_i18n('{rate} of {count} decisions', { values: { rate: formatProbability(acceptance.rate), count: n(decisions) } })}
            </MetaItem>
          )}
        </Box>
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
