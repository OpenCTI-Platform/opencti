import { useState } from 'react';
import { graphql } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import Box from '@mui/material/Box';
import DialogActions from '@mui/material/DialogActions';
import Typography from '@mui/material/Typography';
import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import EETooltip from '@components/common/entreprise_edition/EETooltip';
import { useFormatter } from '../../../../components/i18n';
import TextareaField from '../../../../components/TextareaField';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';
import { MESSAGING$ } from '../../../../relay/environment';
import useCurationLabels from './curationUtils';
import { CurationProposalActionsAcceptMutation } from './__generated__/CurationProposalActionsAcceptMutation.graphql';
import { CurationProposalActionsRejectMutation } from './__generated__/CurationProposalActionsRejectMutation.graphql';
import { CurationProposalActionsRevertMutation } from './__generated__/CurationProposalActionsRevertMutation.graphql';
import { CurationProposalActionsAdjudicateMutation } from './__generated__/CurationProposalActionsAdjudicateMutation.graphql';

const acceptMutation = graphql`
  mutation CurationProposalActionsAcceptMutation($id: ID!, $input: CurationProposalAcceptInput) {
    curationProposalAccept(id: $id, input: $input) {
      ...CurationProposal_proposal
    }
  }
`;

const rejectMutation = graphql`
  mutation CurationProposalActionsRejectMutation($id: ID!, $rationale: String) {
    curationProposalReject(id: $id, rationale: $rationale) {
      ...CurationProposal_proposal
    }
  }
`;

const revertMutation = graphql`
  mutation CurationProposalActionsRevertMutation($id: ID!) {
    curationProposalRevert(id: $id) {
      ...CurationProposal_proposal
    }
  }
`;

const adjudicateMutation = graphql`
  mutation CurationProposalActionsAdjudicateMutation($id: ID!) {
    curationProposalAdjudicate(id: $id) {
      ...CurationProposal_proposal
    }
  }
`;

/** Recommended actions whose surviving entity the analyst chooses. */
const TARGETED_ACTIONS = ['merge', 'add_aliases'];
/** The analyst chooses which attribution survives; the others are deleted. */
const ACTION_RESOLVE_ATTRIBUTION = 'resolve_attribution';

interface CurationProposalActionsProps {
  proposal: {
    id: string;
    name: string;
    proposal_status: string;
    recommended_action: string;
    can_apply: boolean;
    merge_record_id?: string | null;
    applied_patch?: string | null;
    in_ambiguous_band: boolean;
  };
  survivorId: string | null;
  survivorName: string | null;
  adjudicationAvailable: boolean;
}

type DialogKind = 'accept' | 'reject' | 'revert' | null;

const CurationProposalActions = ({ proposal, survivorId, survivorName, adjudicationAvailable }: CurationProposalActionsProps) => {
  const { t_i18n } = useFormatter();
  const labels = useCurationLabels();
  const isEnterpriseEdition = useEnterpriseEdition();
  const [dialog, setDialog] = useState<DialogKind>(null);
  const [commitAccept, accepting] = useApiMutation<CurationProposalActionsAcceptMutation>(acceptMutation);
  const [commitReject, rejecting] = useApiMutation<CurationProposalActionsRejectMutation>(rejectMutation);
  const [commitRevert, reverting] = useApiMutation<CurationProposalActionsRevertMutation>(revertMutation);
  const [commitAdjudicate, adjudicating] = useApiMutation<CurationProposalActionsAdjudicateMutation>(adjudicateMutation);
  const busy = accepting || rejecting || reverting || adjudicating;
  const isOpen = proposal.proposal_status === 'open';
  const isApplied = proposal.proposal_status === 'accepted' || proposal.proposal_status === 'auto_applied';
  const canRevert = isApplied && (!!proposal.merge_record_id || !!proposal.applied_patch);
  const isTargeted = TARGETED_ACTIONS.includes(proposal.recommended_action);
  const isAttribution = proposal.recommended_action === ACTION_RESOLVE_ATTRIBUTION;
  const needsSelection = isTargeted || isAttribution;
  const close = () => setDialog(null);

  const submit = (rationale: string) => {
    const trimmed = rationale.trim() || null;
    if (dialog === 'accept') {
      const input = {
        rationale: trimmed,
        target_id: isTargeted ? survivorId : null,
        action_payload: isAttribution && survivorId ? JSON.stringify({ keep_actor_id: survivorId }) : null,
      };
      commitAccept({
        variables: { id: proposal.id, input },
        onCompleted: () => {
          MESSAGING$.notifySuccess(t_i18n('The curation proposal has been applied'));
          close();
        },
      });
    } else if (dialog === 'reject') {
      commitReject({
        variables: { id: proposal.id, rationale: trimmed },
        onCompleted: () => {
          MESSAGING$.notifySuccess(t_i18n('The curation proposal has been rejected'));
          close();
        },
      });
    } else if (dialog === 'revert') {
      commitRevert({
        variables: { id: proposal.id },
        onCompleted: () => {
          MESSAGING$.notifySuccess(t_i18n('The curation proposal has been reverted'));
          close();
        },
      });
    }
  };

  const adjudicate = () => {
    commitAdjudicate({
      variables: { id: proposal.id },
      onCompleted: () => MESSAGING$.notifySuccess(t_i18n('The OpenCTI Curator has adjudicated the proposal')),
    });
  };

  const dialogTitles: Record<Exclude<DialogKind, null>, string> = {
    accept: t_i18n('Accept the curation proposal'),
    reject: t_i18n('Reject the curation proposal'),
    revert: t_i18n('Revert the curation proposal'),
  };

  return (
    <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap', alignItems: 'center' }} data-testid="curation-proposal-actions">
      {isOpen && proposal.in_ambiguous_band && adjudicationAvailable && (
        <EETooltip title="Ask the OpenCTI Curator agent of XTM One to adjudicate this proposal">
          <span>
            <Button variant="secondary" intent="ai" onClick={adjudicate} disabled={busy || !isEnterpriseEdition}>
              {t_i18n('Ask the Curator')}
            </Button>
          </span>
        </EETooltip>
      )}
      {isOpen && proposal.can_apply && (
        <>
          <Button variant="secondary" onClick={() => setDialog('reject')} disabled={busy}>
            {t_i18n('Reject')}
          </Button>
          <Button onClick={() => setDialog('accept')} disabled={busy || (needsSelection && !survivorId)}>
            {t_i18n('Accept')}
          </Button>
        </>
      )}
      {isOpen && proposal.can_apply && isAttribution && !survivorId && (
        <Typography variant="body2" color="text.secondary">
          {t_i18n('Choose the attribution to keep in the comparison below')}
        </Typography>
      )}
      {canRevert && proposal.can_apply && (
        <Button variant="secondary" intent="destructive" onClick={() => setDialog('revert')} disabled={busy}>
          {t_i18n('Revert')}
        </Button>
      )}
      {isOpen && !proposal.can_apply && (
        <Typography variant="body2" color="text.secondary">
          {t_i18n('You do not have the capability to apply this proposal')}
        </Typography>
      )}
      <Formik<{ rationale: string }>
        initialValues={{ rationale: '' }}
        enableReinitialize
        onSubmit={(values, { resetForm }) => {
          submit(values.rationale);
          resetForm();
        }}
      >
        {({ submitForm }) => (
          <Dialog open={dialog !== null} onClose={close} title={dialog ? dialogTitles[dialog] : ''}>
            <Typography variant="body2" sx={{ marginBottom: 2 }}>
              {dialog === 'accept' && `${t_i18n('Action')}: ${labels.action(proposal.recommended_action)}`}
              {dialog === 'accept' && isTargeted && survivorName && ` - ${t_i18n('Survivor')}: ${survivorName}`}
              {dialog === 'accept' && isAttribution && survivorName && ` - ${t_i18n('Attribution kept')}: ${survivorName}`}
              {dialog === 'revert' && t_i18n('The change applied by this proposal is undone; merged entities are restored from their snapshots.')}
              {dialog === 'reject' && t_i18n('The proposal is closed and the same subjects are not proposed again for the same reason.')}
            </Typography>
            {dialog !== 'revert' && (
              <Form>
                <Field component={TextareaField} name="rationale" label={t_i18n('Rationale (optional)')} rows={3} />
              </Form>
            )}
            <DialogActions>
              <Button variant="secondary" onClick={close} disabled={busy}>
                {t_i18n('Cancel')}
              </Button>
              <Button onClick={submitForm} disabled={busy} intent={dialog === 'revert' ? 'destructive' : 'default'}>
                {dialog ? t_i18n(dialog === 'accept' ? 'Accept' : (dialog === 'reject' ? 'Reject' : 'Revert')) : ''}
              </Button>
            </DialogActions>
          </Dialog>
        )}
      </Formik>
    </Box>
  );
};

export default CurationProposalActions;
