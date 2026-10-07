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
import { ThumbDownOutlined, ThumbUpOutlined } from '@mui/icons-material';
import DialogActions from '@mui/material/DialogActions';
import { Textarea } from '@filigran/design-system';
import IconButton from '@common/button/IconButton';
import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import { useFormatter } from '../../../components/i18n';
import useApiMutation from '../../../utils/hooks/useApiMutation';
import useGranted, { KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';
import { reportMutationOutcome } from './investigationRunUtils';
import { InvestigationRunFeedbackMutation } from './__generated__/InvestigationRunFeedbackMutation.graphql';

const investigationRunFeedbackMutation = graphql`
  mutation InvestigationRunFeedbackMutation($id: ID!, $input: InvestigationRunFeedbackInput!) {
    investigationRunFeedback(id: $id, input: $input) {
      id
      ...InvestigationRunView_run
    }
  }
`;

export type InvestigationFeedbackItemType = 'hypothesis' | 'recommendation';

interface InvestigationRunFeedbackProps {
  runId: string;
  itemType: InvestigationFeedbackItemType;
  itemRef: string;
  itemLabel: string;
  decision: string | null;
  disabled?: boolean;
}

/**
 * Accept or reject one hypothesis or recommendation: the analyst's calibration signal.
 * Rendered only for readers allowed to update knowledge, as the feedback mutation requires.
 */
const InvestigationRunFeedback = ({ runId, itemType, itemRef, itemLabel, decision, disabled = false }: InvestigationRunFeedbackProps) => {
  const { t_i18n } = useFormatter();
  const canGiveFeedback = useGranted([KNOWLEDGE_KNUPDATE]);
  const [rejecting, setRejecting] = useState(false);
  const [comment, setComment] = useState('');
  const [commit, inFlight] = useApiMutation<InvestigationRunFeedbackMutation>(investigationRunFeedbackMutation);
  const send = (value: 'accepted' | 'rejected', text: string | null) => {
    commit({
      variables: { id: runId, input: { item_type: itemType, item_ref: itemRef, decision: value, comment: text } },
      onCompleted: (_, errors) => {
        // A rejection that was not saved keeps its dialog and comment.
        if (!reportMutationOutcome(errors, t_i18n('Your feedback was recorded'))) return;
        setRejecting(false);
        setComment('');
      },
    });
  };
  if (!canGiveFeedback) return null;
  const acceptLabel = t_i18n('Accept {item}', { values: { item: itemLabel } });
  const rejectLabel = t_i18n('Reject {item}', { values: { item: itemLabel } });
  return (
    <span style={{ display: 'inline-flex', gap: 4 }}>
      <IconButton
        size="small"
        variant="tertiary"
        aria-label={acceptLabel}
        aria-pressed={decision === 'accepted'}
        selected={decision === 'accepted'}
        color={decision === 'accepted' ? 'success' : undefined}
        disabled={disabled || inFlight}
        onClick={() => send('accepted', null)}
        data-testid={`investigation-feedback-accept-${itemRef}`}
      >
        <ThumbUpOutlined fontSize="small" />
      </IconButton>
      <IconButton
        size="small"
        variant="tertiary"
        aria-label={rejectLabel}
        aria-pressed={decision === 'rejected'}
        selected={decision === 'rejected'}
        color={decision === 'rejected' ? 'error' : undefined}
        disabled={disabled || inFlight}
        onClick={() => setRejecting(true)}
        data-testid={`investigation-feedback-reject-${itemRef}`}
      >
        <ThumbDownOutlined fontSize="small" />
      </IconButton>
      <Dialog
        open={rejecting}
        onClose={() => setRejecting(false)}
        title={t_i18n('Reject this item')}
        size="small"
      >
        <Textarea
          label={t_i18n('Why is it wrong? (optional)')}
          helperText={t_i18n('Your comment calibrates the next investigations of this platform.')}
          value={comment}
          maxLength={2000}
          onChange={(event) => setComment(event.target.value)}
        />
        <DialogActions>
          <Button variant="secondary" onClick={() => setRejecting(false)} disabled={inFlight}>
            {t_i18n('Cancel')}
          </Button>
          <Button intent="destructive" onClick={() => send('rejected', comment.trim() || null)} disabled={inFlight}>
            {t_i18n('Reject')}
          </Button>
        </DialogActions>
      </Dialog>
    </span>
  );
};

export default InvestigationRunFeedback;
