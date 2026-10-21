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

import React, { forwardRef, Suspense, useState } from 'react';
import Box from '@mui/material/Box';
import Divider from '@mui/material/Divider';
import Skeleton from '@mui/material/Skeleton';
import Stack from '@mui/material/Stack';
import Typography from '@mui/material/Typography';
import DialogActions from '@mui/material/DialogActions';
import { CheckCircleOutlined, HighlightOffOutlined } from '@mui/icons-material';
import { Chip, Textarea, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import Card from '@common/card/Card';
import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import { useFormatter } from '../../../components/i18n';
import { MESSAGING$ } from '../../../relay/environment';
import useGranted, { KNOWLEDGE_KNENRICHMENT, KNOWLEDGE_KNUPDATE, KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../utils/hooks/useGranted';
import InvestigationRunDraftPreview from './InvestigationRunDraftPreview';
import { draftChangeCount, draftChangeSummary } from './investigationRunDraftChanges';
import {
  APPROVAL_KIND_LABELS,
  approvedDraftOutcome,
  closedByTheRunLabel,
  decideInvestigationApprovals,
  type InvestigationApprovalDecision,
  SEVERITY_LABELS,
} from './investigationRunUtils';
import type { InvestigationRunView_run$data } from './__generated__/InvestigationRunView_run.graphql';

type Run = InvestigationRunView_run$data;
type Approval = Run['approvals'][number];

// Decided gates kept visible, one line each, under the pending ones.
const DECIDED_VISIBLE = 3;

const requiredCapability = (kind: string) => {
  if (kind === 'enrichment') return KNOWLEDGE_KNENRICHMENT;
  if (kind === 'draft_validation') return KNOWLEDGE_KNUPDATE_KNDELETE;
  return KNOWLEDGE_KNUPDATE;
};

const RelativeTime = ({ date, template }: { date: string; template?: string }) => {
  const { t_i18n, rd, fldt } = useFormatter();
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Typography variant="caption" color="text.secondary" component="span" tabIndex={0}>
          {template ? t_i18n(template, { values: { time: rd(date) } }) : rd(date)}
        </Typography>
      </TooltipTrigger>
      <TooltipContent>{fldt(date)}</TooltipContent>
    </Tooltip>
  );
};

const connectorNameOf = (run: Run, approval: Approval) => run.enrichment_requests.find((request) => request.connector_id === approval.connector_id)?.connector_name;

/** The title of a gate and what approving it changes, in words. */
const useGateText = (run: Run, approval: Approval, entityNames: Map<string, string>) => {
  const { t_i18n } = useFormatter();
  if (approval.kind === 'enrichment') {
    const connector = connectorNameOf(run, approval) ?? t_i18n('An enrichment connector');
    const entity = (approval.entity_id && entityNames.get(approval.entity_id)) || t_i18n('a restricted entity');
    return {
      title: t_i18n('Run {connector} on {entity}', { values: { connector, entity } }),
      change: t_i18n('This connector needs an approval in the investigation policy.'),
    };
  }
  const recommendation = run.recommendations.find((item) => item.id === approval.recommendation_id);
  if (recommendation?.action_kind === 'severity_change' && recommendation.severity) {
    return {
      title: recommendation.text,
      change: t_i18n('The severity of the case changes to {severity}.', { values: { severity: t_i18n(SEVERITY_LABELS[recommendation.severity] ?? 'Medium') } }),
    };
  }
  return {
    title: recommendation?.text ?? approval.description,
    change: t_i18n('A task is created on the case for an analyst to carry out: Case Autopilot never shares, notifies or closes by itself.'),
  };
};

interface DecisionControlsProps {
  run: Run;
  approval: Approval;
  approveLabel: string;
  onDecided: () => void;
}

const DecisionControls = ({ run, approval, approveLabel, onDecided }: DecisionControlsProps) => {
  const { t_i18n } = useFormatter();
  const canDecide = useGranted([requiredCapability(approval.kind)]);
  const [busy, setBusy] = useState(false);
  const [rejecting, setRejecting] = useState(false);
  const [reason, setReason] = useState('');
  const decide = async (decision: InvestigationApprovalDecision, rejectionReason: string | null = null) => {
    setBusy(true);
    try {
      await decideInvestigationApprovals(run.id, [{ tool_call_id: approval.id, decision, rejection_reason: rejectionReason }]);
      MESSAGING$.notifySuccess(decision === 'reject' ? t_i18n('The request was rejected') : t_i18n('The request was approved'));
      setRejecting(false);
      setReason('');
      onDecided();
    } catch (error) {
      MESSAGING$.notifyError(t_i18n('The approval was not recorded: {reason}', { values: { reason: (error as Error).message } }));
    } finally {
      setBusy(false);
    }
  };
  if (!canDecide) {
    return <Typography variant="body2" color="text.secondary">{t_i18n('You are not allowed to decide this request')}</Typography>;
  }
  const connector = approval.kind === 'enrichment' ? connectorNameOf(run, approval) : null;
  return (
    <>
      <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
        <Button size="small" onClick={() => decide('approve')} disabled={busy} data-testid={`investigation-approve-${approval.kind}`}>{approveLabel}</Button>
        {approval.kind === 'enrichment' && (
          <Button size="small" variant="secondary" onClick={() => decide('approve_always')} disabled={busy}>
            {connector ? t_i18n('Always approve {connector}', { values: { connector } }) : t_i18n('Always approve this connector')}
          </Button>
        )}
        <Button size="small" variant="secondary" intent="destructive" onClick={() => setRejecting(true)} disabled={busy} data-testid={`investigation-reject-${approval.kind}`}>
          {t_i18n('Reject')}
        </Button>
      </Stack>
      <Dialog
        open={rejecting}
        onClose={() => setRejecting(false)}
        title={approval.kind === 'draft_validation' ? t_i18n('Reject the changes') : t_i18n('Reject the request')}
        size="small"
      >
        <Stack spacing={2}>
          <Typography variant="body2">{t_i18n('Your reason calibrates the next investigations of this platform.')}</Typography>
          <Textarea
            label={t_i18n('Reason (optional)')}
            value={reason}
            maxLength={2000}
            onChange={(event) => setReason(event.target.value)}
          />
        </Stack>
        <DialogActions>
          <Button variant="secondary" onClick={() => setRejecting(false)} disabled={busy}>{t_i18n('Cancel')}</Button>
          <Button intent="destructive" onClick={() => decide('reject', reason.trim() || null)} disabled={busy}>{t_i18n('Reject')}</Button>
        </DialogActions>
      </Dialog>
    </>
  );
};

const DraftApproval = ({ run, approval, onDecided }: { run: Run; approval: Approval; onDecided: () => void }) => {
  const { t_i18n, n } = useFormatter();
  const counts = run.draft?.objectsCount;
  const total = draftChangeCount(counts);
  const summary = counts ? draftChangeSummary(counts, t_i18n) : '';
  let title = t_i18n('Approve the investigation draft');
  if (total > 0) title = t_i18n(run.case ? 'Approve {count} changes to this case' : 'Approve {count} changes', { values: { count: n(total) } });
  return (
    <Stack spacing={1.5} data-testid="investigation-approval-draft_validation">
      <Stack spacing={0.25}>
        <Typography variant="h3" component="h3">{title}</Typography>
        <RelativeTime date={approval.created_at} template="Proposed by Case Autopilot {time}" />
      </Stack>
      {summary && <Typography variant="body2" data-testid="investigation-draft-summary">{summary}</Typography>}
      {run.draft_id && (
        <Suspense fallback={<Stack spacing={1}>{[0, 1, 2].map((key) => <Skeleton key={key} variant="text" width={`${70 - key * 15}%`} />)}</Stack>}>
          <InvestigationRunDraftPreview draftId={run.draft_id} total={total} />
        </Suspense>
      )}
      <DecisionControls
        run={run}
        approval={approval}
        approveLabel={total > 0 ? t_i18n('Approve {count} changes', { values: { count: n(total) } }) : t_i18n('Approve the draft')}
        onDecided={onDecided}
      />
    </Stack>
  );
};

const GateApproval = ({ run, approval, entityNames, onDecided }: { run: Run; approval: Approval; entityNames: Map<string, string>; onDecided: () => void }) => {
  const { t_i18n } = useFormatter();
  const text = useGateText(run, approval, entityNames);
  return (
    <Stack spacing={1} data-testid={`investigation-approval-${approval.kind}`}>
      <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap>
        <Chip label={t_i18n(APPROVAL_KIND_LABELS[approval.kind] ?? 'Sensitive recommendation')} severity="medium" size="sm" />
        <Typography variant="body1" sx={{ fontWeight: 'fontWeightBold', overflowWrap: 'anywhere' }}>{text.title}</Typography>
      </Stack>
      <Typography variant="body2" color="text.secondary">{text.change}</Typography>
      {approval.reason && <Typography variant="body2" color="text.secondary">{approval.reason}</Typography>}
      <RelativeTime date={approval.created_at} template="Requested by Case Autopilot {time}" />
      <DecisionControls
        run={run}
        approval={approval}
        approveLabel={approval.kind === 'enrichment' ? t_i18n('Approve once') : t_i18n('Approve')}
        onDecided={onDecided}
      />
    </Stack>
  );
};

const DecidedLine = ({ run, approval, entityNames }: { run: Run; approval: Approval; entityNames: Map<string, string> }) => {
  const { t_i18n } = useFormatter();
  const text = useGateText(run, approval, entityNames);
  const approved = approval.status === 'approved';
  const who = approval.decider?.name ?? t_i18n('an analyst');
  const subject = approval.kind === 'draft_validation'
    ? t_i18n(approved ? approvedDraftOutcome(run) : 'the draft stays open for review')
    : text.title;
  const closedByTheRun = approved ? null : closedByTheRunLabel(approval.rejection_reason, !!approval.decider);
  let line = t_i18n(approved ? 'Approved by {user}: {subject}' : 'Rejected by {user}: {subject}', { values: { user: who, subject } });
  if (closedByTheRun) {
    line = t_i18n(closedByTheRun, { values: { subject } });
  } else if (!approved && approval.rejection_reason) {
    line = `${line} - ${approval.rejection_reason}`;
  }
  return (
    <Stack component="li" direction="row" spacing={1} alignItems="center" sx={{ paddingY: 0.25 }} data-testid="investigation-approval-decided">
      {approved
        ? <CheckCircleOutlined fontSize="small" color="success" titleAccess={t_i18n('Approved')} />
        : <HighlightOffOutlined fontSize="small" color="action" titleAccess={t_i18n('Rejected')} />}
      <Typography variant="body2" sx={{ minWidth: 0, overflowWrap: 'anywhere' }}>{line}</Typography>
      {approval.decided_at && <RelativeTime date={approval.decided_at} />}
    </Stack>
  );
};

interface InvestigationRunApprovalsProps {
  run: Run;
  entityNames: Map<string, string>;
  onDecided: () => void;
}

/**
 * The gates of an investigation: what approving each one changes, next to
 * Approve and Reject. Decided gates fold into one line each.
 */
const InvestigationRunApprovals = forwardRef<HTMLDivElement, InvestigationRunApprovalsProps>(({ run, entityNames, onDecided }, ref) => {
  const { t_i18n } = useFormatter();
  const pending = run.approvals.filter((approval) => approval.status === 'pending');
  const decided = run.approvals
    .filter((approval) => approval.status !== 'pending' && approval.decided_at)
    .sort((a, b) => (b.decided_at ?? '').localeCompare(a.decided_at ?? ''))
    .slice(0, DECIDED_VISIBLE);
  if (pending.length === 0 && decided.length === 0) return null;
  const draftGate = pending.find((approval) => approval.kind === 'draft_validation');
  const otherGates = pending.filter((approval) => approval.kind !== 'draft_validation');
  return (
    <Box ref={ref} tabIndex={-1} id="investigation-run-approvals" sx={{ outline: 'none' }} aria-label={t_i18n('Approvals')}>
      <Card title={pending.length > 0 ? t_i18n('Waiting for your approval') : t_i18n('Approvals')}>
        <Stack spacing={2} divider={<Divider flexItem />}>
          {draftGate && <DraftApproval run={run} approval={draftGate} onDecided={onDecided} />}
          {otherGates.map((approval) => (
            <GateApproval key={approval.id} run={run} approval={approval} entityNames={entityNames} onDecided={onDecided} />
          ))}
          {decided.length > 0 && (
            <Box component="ul" sx={{ listStyle: 'none', margin: 0, padding: 0 }} aria-label={t_i18n('Decided approvals')}>
              {decided.map((approval) => <DecidedLine key={approval.id} run={run} approval={approval} entityNames={entityNames} />)}
            </Box>
          )}
        </Stack>
      </Card>
    </Box>
  );
});

InvestigationRunApprovals.displayName = 'InvestigationRunApprovals';

export default InvestigationRunApprovals;
