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
import Stack from '@mui/material/Stack';
import Typography from '@mui/material/Typography';
import DialogActions from '@mui/material/DialogActions';
import { Chip, Textarea } from '@filigran/design-system';
import Card from '@common/card/Card';
import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import { useFormatter } from '../../../components/i18n';
import { MESSAGING$ } from '../../../relay/environment';
import useGranted, { KNOWLEDGE_KNENRICHMENT, KNOWLEDGE_KNUPDATE, KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../utils/hooks/useGranted';
import { APPROVAL_KIND_LABELS, decideInvestigationApprovals, type InvestigationApprovalDecision } from './investigationRunUtils';
import type { InvestigationRunView_run$data } from './__generated__/InvestigationRunView_run.graphql';

type Approval = InvestigationRunView_run$data['approvals'][number];

interface InvestigationRunApprovalsProps {
  runId: string;
  approvals: InvestigationRunView_run$data['approvals'];
  onDecided: () => void;
}

const requiredCapability = (kind: string) => {
  if (kind === 'enrichment') return KNOWLEDGE_KNENRICHMENT;
  if (kind === 'draft_validation') return KNOWLEDGE_KNUPDATE_KNDELETE;
  return KNOWLEDGE_KNUPDATE;
};

const ApprovalRow = ({ approval, runId, onDecided }: { approval: Approval; runId: string; onDecided: () => void }) => {
  const { t_i18n, fldt } = useFormatter();
  const canDecide = useGranted([requiredCapability(approval.kind)]);
  const [busy, setBusy] = useState(false);
  const [rejecting, setRejecting] = useState(false);
  const [reason, setReason] = useState('');
  const decide = async (decision: InvestigationApprovalDecision, rejectionReason: string | null = null) => {
    setBusy(true);
    try {
      await decideInvestigationApprovals(runId, [{ tool_call_id: approval.id, decision, rejection_reason: rejectionReason }]);
      MESSAGING$.notifySuccess(decision === 'reject' ? t_i18n('The request was rejected') : t_i18n('The request was approved'));
      setRejecting(false);
      setReason('');
      onDecided();
    } catch (error) {
      MESSAGING$.notifyError(`${t_i18n('The approval was not recorded')}: ${(error as Error).message}`);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Stack direction={{ xs: 'column', md: 'row' }} spacing={2} alignItems={{ md: 'center' }} justifyContent="space-between" data-testid={`investigation-approval-${approval.kind}`}>
      <Stack spacing={0.5} sx={{ flex: 1 }}>
        <Stack direction="row" spacing={1} alignItems="center">
          <Chip label={t_i18n(APPROVAL_KIND_LABELS[approval.kind] ?? approval.kind)} severity="medium" size="sm" />
          <Typography variant="body1">{approval.description}</Typography>
        </Stack>
        {approval.reason && <Typography variant="body2" color="text.secondary">{approval.reason}</Typography>}
        <Typography variant="caption" color="text.secondary">{fldt(approval.created_at)}</Typography>
      </Stack>
      {canDecide ? (
        <Stack direction="row" spacing={1}>
          <Button size="small" onClick={() => decide('approve')} disabled={busy}>{t_i18n('Approve')}</Button>
          {approval.kind === 'enrichment' && (
            <Button size="small" variant="secondary" onClick={() => decide('approve_always')} disabled={busy}>
              {t_i18n('Approve for this connector')}
            </Button>
          )}
          <Button size="small" variant="secondary" intent="destructive" onClick={() => setRejecting(true)} disabled={busy}>
            {t_i18n('Reject')}
          </Button>
        </Stack>
      ) : (
        <Typography variant="body2" color="text.secondary">{t_i18n('You are not allowed to decide this request')}</Typography>
      )}
      <Dialog open={rejecting} onClose={() => setRejecting(false)} title={t_i18n('Reject the request')} size="small">
        <Textarea
          label={t_i18n('Reason (optional)')}
          value={reason}
          maxLength={2000}
          onChange={(event) => setReason(event.target.value)}
        />
        <DialogActions>
          <Button variant="secondary" onClick={() => setRejecting(false)} disabled={busy}>{t_i18n('Cancel')}</Button>
          <Button intent="destructive" onClick={() => decide('reject', reason.trim() || null)} disabled={busy}>{t_i18n('Reject')}</Button>
        </DialogActions>
      </Dialog>
    </Stack>
  );
};

/** Approval gates the run is waiting for: paid enrichments, sensitive recommendations, the investigation draft. */
const InvestigationRunApprovals = ({ runId, approvals, onDecided }: InvestigationRunApprovalsProps) => {
  const { t_i18n } = useFormatter();
  const pending = approvals.filter((approval) => approval.status === 'pending');
  return (
    <Card title={`${t_i18n('Waiting for your approval')} (${pending.length})`}>
      <Stack spacing={2}>
        {pending.map((approval) => (
          <ApprovalRow key={approval.id} approval={approval} runId={runId} onDecided={onDecided} />
        ))}
      </Stack>
    </Card>
  );
};

export default InvestigationRunApprovals;
