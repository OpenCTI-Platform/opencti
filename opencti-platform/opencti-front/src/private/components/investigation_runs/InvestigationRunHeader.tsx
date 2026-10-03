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
import { Link } from 'react-router';
import Box from '@mui/material/Box';
import Stack from '@mui/material/Stack';
import Typography from '@mui/material/Typography';
import DialogActions from '@mui/material/DialogActions';
import { CancelOutlined, DeleteOutlined, DoneAllOutlined, HubOutlined, OpenInNewOutlined, PlayArrowOutlined } from '@mui/icons-material';
import { ProgressBar, Spinner } from '@filigran/design-system';
import Card from '@common/card/Card';
import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import { useFormatter } from '../../../components/i18n';
import Security from '../../../utils/Security';
import { KNOWLEDGE_KNENRICHMENT, KNOWLEDGE_KNUPDATE, KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../utils/hooks/useGranted';
import useApiMutation from '../../../utils/hooks/useApiMutation';
import { MESSAGING$ } from '../../../relay/environment';
import InvestigationRunStatusChip from './InvestigationRunStatusChip';
import {
  budgetPercent,
  decideInvestigationApprovals,
  DEFAULT_PACK,
  elementPath,
  engineReasonLabel,
  formatProbability,
  investigationGraphPath,
  isRunActive,
  reportMutationOutcome,
  RUN_TRIGGER_LABELS,
  runPhaseLabel,
} from './investigationRunUtils';
import type { InvestigationRunView_run$data } from './__generated__/InvestigationRunView_run.graphql';
import { InvestigationRunHeaderCancelMutation } from './__generated__/InvestigationRunHeaderCancelMutation.graphql';
import { InvestigationRunHeaderDeleteMutation } from './__generated__/InvestigationRunHeaderDeleteMutation.graphql';
import { InvestigationRunHeaderContinueMutation } from './__generated__/InvestigationRunHeaderContinueMutation.graphql';

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

interface InvestigationRunHeaderProps {
  run: InvestigationRunView_run$data;
  currentEntityId?: string;
  onDecided: () => void;
  onDeleted?: () => void;
}

const InfoItem = ({ label, children }: { label: string; children: React.ReactNode }) => (
  <Box sx={{ minWidth: 160 }}>
    <Typography variant="h4" gutterBottom>{label}</Typography>
    <Box sx={{ wordBreak: 'break-word' }}>{children}</Box>
  </Box>
);

const InvestigationRunHeader = ({ run, currentEntityId, onDecided, onDeleted }: InvestigationRunHeaderProps) => {
  const { t_i18n, fldt, n } = useFormatter();
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [approving, setApproving] = useState(false);
  const [commitCancel, cancelling] = useApiMutation<InvestigationRunHeaderCancelMutation>(investigationRunHeaderCancelMutation);
  const [commitDelete, deleting] = useApiMutation<InvestigationRunHeaderDeleteMutation>(investigationRunHeaderDeleteMutation);
  const [commitContinue, continuing] = useApiMutation<InvestigationRunHeaderContinueMutation>(investigationRunHeaderContinueMutation);
  const engineReason = engineReasonLabel(run.end_reason_code);
  const active = isRunActive(run.run_status);
  const draftApproval = run.approvals.find((approval) => approval.kind === 'draft_validation' && approval.status === 'pending');
  const draftOpen = run.draft && run.draft.draft_status !== 'validated';
  const { budget } = run;
  const acceptance = run.acceptance;
  const decisions = acceptance.hypotheses_accepted + acceptance.hypotheses_rejected + acceptance.recommendations_accepted + acceptance.recommendations_rejected;
  const approveDraft = async () => {
    if (!draftApproval) return;
    setApproving(true);
    try {
      await decideInvestigationApprovals(run.id, [{ tool_call_id: draftApproval.id, decision: 'approve' }]);
      MESSAGING$.notifySuccess(t_i18n('The investigation draft is being validated'));
      onDecided();
    } catch (error) {
      MESSAGING$.notifyError(`${t_i18n('The approval was not recorded')}: ${(error as Error).message}`);
    } finally {
      setApproving(false);
    }
  };
  const budgetBars = [
    { key: 'iterations', label: t_i18n('Iterations'), used: budget.used_iterations, max: budget.max_iterations },
    { key: 'enrichments', label: t_i18n('Enrichment jobs'), used: budget.used_enrichment_jobs, max: budget.max_enrichment_jobs },
    { key: 'minutes', label: t_i18n('Minutes'), used: Math.round(budget.used_minutes * 10) / 10, max: budget.max_minutes },
  ];
  return (
    <Card
      title={run.name}
      action={(
        <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
          {draftApproval && (
            <Security needs={[KNOWLEDGE_KNUPDATE_KNDELETE]}>
              <Button size="small" startIcon={<DoneAllOutlined fontSize="small" />} onClick={approveDraft} disabled={approving} data-testid="investigation-run-approve-draft">
                {t_i18n('Approve the draft')}
              </Button>
            </Security>
          )}
          {run.can_continue && (
            <Security needs={[KNOWLEDGE_KNUPDATE, KNOWLEDGE_KNENRICHMENT]} matchAll>
              <Button
                size="small"
                variant="secondary"
                intent="ai"
                startIcon={<PlayArrowOutlined fontSize="small" />}
                disabled={continuing}
                onClick={() => commitContinue({
                  variables: { id: run.id },
                  onCompleted: (_, errors) => {
                    reportMutationOutcome(errors, t_i18n('The investigation continues'));
                  },
                })}
                data-testid="investigation-run-continue"
              >
                {t_i18n('Continue investigation')}
              </Button>
            </Security>
          )}
          {draftOpen && run.draft && (
            <Button size="small" variant="secondary" component={Link} to={`/dashboard/data/import/draft/${run.draft.id}`} startIcon={<OpenInNewOutlined fontSize="small" />}>
              {t_i18n('Open the draft')}
            </Button>
          )}
          {run.workspace_id && (
            <Button size="small" variant="secondary" component={Link} to={investigationGraphPath(run.workspace_id)} startIcon={<HubOutlined fontSize="small" />}>
              {t_i18n('Open the investigation graph')}
            </Button>
          )}
          {active && (
            <Security needs={[KNOWLEDGE_KNUPDATE]}>
              <Button
                size="small"
                variant="secondary"
                intent="destructive"
                startIcon={<CancelOutlined fontSize="small" />}
                disabled={cancelling}
                onClick={() => commitCancel({
                  variables: { id: run.id },
                  onCompleted: (_, errors) => {
                    reportMutationOutcome(errors, t_i18n('The investigation was cancelled'));
                  },
                })}
                data-testid="investigation-run-cancel"
              >
                {t_i18n('Cancel the investigation')}
              </Button>
            </Security>
          )}
          {!active && (
            <Security needs={[KNOWLEDGE_KNUPDATE_KNDELETE]}>
              <Button size="small" variant="tertiary" intent="destructive" startIcon={<DeleteOutlined fontSize="small" />} onClick={() => setConfirmDelete(true)}>
                {t_i18n('Delete')}
              </Button>
            </Security>
          )}
        </Stack>
      )}
    >
      <Stack spacing={3}>
        <Stack direction="row" spacing={2} alignItems="center" flexWrap="wrap" useFlexGap>
          <InvestigationRunStatusChip status={run.run_status} />
          {active && <Spinner size="sm" />}
          <Typography variant="body2">{t_i18n(runPhaseLabel(run.run_phase))}</Typography>
          <Typography variant="body2" color="text.secondary">
            {`${t_i18n('Trigger')}: ${t_i18n(RUN_TRIGGER_LABELS[run.run_trigger] ?? run.run_trigger)}`}
          </Typography>
        </Stack>
        {engineReason && (
          <Typography variant="body2" color="warning.main" data-testid="investigation-run-engine-reason">
            {t_i18n(engineReason)}
          </Typography>
        )}
        {run.status_reason && !engineReason && (
          <Typography variant="body2" color={run.run_status === 'failed' ? 'error' : 'text.secondary'} data-testid="investigation-run-status-reason">
            {run.status_reason}
          </Typography>
        )}
        <Stack direction="row" spacing={4} flexWrap="wrap" useFlexGap>
          <InfoItem label={t_i18n('Investigated entity')}>
            {run.subject && run.subject.id !== currentEntityId
              ? <Link to={elementPath(run.subject.id)}>{run.subject.representative.main}</Link>
              : (run.subject?.representative.main ?? t_i18n('Restricted'))}
          </InfoItem>
          <InfoItem label={t_i18n('Case')}>
            {run.case
              ? (run.case.id === currentEntityId ? run.case.name : <Link to={elementPath(run.case.id)}>{run.case.name}</Link>)
              : '-'}
          </InfoItem>
          <InfoItem label={t_i18n('Investigation policy')}>{run.policy?.name ?? '-'}</InfoItem>
          <InfoItem label={t_i18n('Pack')}>
            {run.pack_id && run.pack_id !== DEFAULT_PACK ? run.pack_id : t_i18n('OpenCTI case investigation')}
          </InfoItem>
          <InfoItem label={t_i18n('Run as')}>{run.runAs?.name ?? '-'}</InfoItem>
          <InfoItem label={t_i18n('Start date')}>{run.started_at ? fldt(run.started_at) : '-'}</InfoItem>
          <InfoItem label={t_i18n('Completion date')}>{run.completed_at ? fldt(run.completed_at) : '-'}</InfoItem>
          {decisions > 0 && (
            <InfoItem label={t_i18n('Analyst acceptance')}>
              {acceptance.rate !== null && acceptance.rate !== undefined ? formatProbability(acceptance.rate) : '-'}
            </InfoItem>
          )}
        </Stack>
        <Stack direction={{ xs: 'column', md: 'row' }} spacing={3}>
          {budgetBars.map((bar) => (
            <Box key={bar.key} sx={{ flex: 1 }}>
              <Stack direction="row" justifyContent="space-between">
                <Typography variant="body2" id={`investigation-budget-${bar.key}`}>{bar.label}</Typography>
                <Typography variant="body2" color="text.secondary">{`${n(bar.used)} / ${n(bar.max)}`}</Typography>
              </Stack>
              <ProgressBar
                aria-labelledby={`investigation-budget-${bar.key}`}
                value={budgetPercent(bar.used, bar.max)}
                tone={budgetPercent(bar.used, bar.max) >= 100 ? 'error' : 'default'}
              />
            </Box>
          ))}
        </Stack>
      </Stack>
      <Dialog open={confirmDelete} onClose={() => setConfirmDelete(false)} title={t_i18n('Delete the investigation')} size="small">
        <span>{t_i18n('The investigation, its goal plan, its evidence and its analyst feedback are deleted. The knowledge it wrote stays.')}</span>
        <DialogActions>
          <Button variant="secondary" onClick={() => setConfirmDelete(false)} disabled={deleting}>{t_i18n('Cancel')}</Button>
          <Button
            intent="destructive"
            disabled={deleting}
            onClick={() => commitDelete({
              variables: { id: run.id },
              onCompleted: (_, errors) => {
                setConfirmDelete(false);
                if (reportMutationOutcome(errors, t_i18n('The investigation was deleted'))) onDeleted?.();
              },
            })}
          >
            {t_i18n('Delete')}
          </Button>
        </DialogActions>
      </Dialog>
    </Card>
  );
};

export default InvestigationRunHeader;
