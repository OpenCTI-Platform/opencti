import { useState } from 'react';
import { graphql } from 'react-relay';
import { useNavigate } from 'react-router';
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
import useGranted, { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import { MESSAGING$ } from '../../../../relay/environment';
import useCurationLabels, { CURATION_MERGES_PATH, notifyPayloadErrors } from './curationUtils';
import type { CurationMergePreview } from './CurationProposalCompare';
import CurationProposalExplanation, { type CurationExplanationData, useExplanationTranslator } from './CurationProposalExplanation';
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

const ACTION_MERGE = 'merge';
const ACTION_ADD_ALIASES = 'add_aliases';
/** Recommended actions whose surviving entity the analyst chooses. */
const TARGETED_ACTIONS = [ACTION_MERGE, ACTION_ADD_ALIASES];
/** The analyst chooses which attribution survives; the others are deleted. */
const ACTION_RESOLVE_ATTRIBUTION = 'resolve_attribution';

interface CurationProposalActionsProps {
  proposal: {
    id: string;
    name: string;
    proposal_status: string;
    recommended_action: string;
    merge_record_id?: string | null;
    can_apply: boolean;
    can_revert: boolean;
    adjudicable: boolean;
  };
  survivorId: string | null;
  survivorName: string | null;
  preview: CurationMergePreview | null;
  adjudicationAvailable: boolean;
  explanation?: CurationExplanationData | null;
}

type DialogKind = 'accept' | 'reject' | 'revert' | null;

const CurationProposalActions = ({ proposal, survivorId, survivorName, preview, adjudicationAvailable, explanation = null }: CurationProposalActionsProps) => {
  const { t_i18n } = useFormatter();
  const labels = useCurationLabels();
  const translate = useExplanationTranslator();
  const navigate = useNavigate();
  const isEnterpriseEdition = useEnterpriseEdition();
  const canDecide = useGranted([KNOWLEDGE_KNUPDATE]);
  const [dialog, setDialog] = useState<DialogKind>(null);
  const [commitAccept, accepting] = useApiMutation<CurationProposalActionsAcceptMutation>(acceptMutation);
  const [commitReject, rejecting] = useApiMutation<CurationProposalActionsRejectMutation>(rejectMutation);
  const [commitRevert, reverting] = useApiMutation<CurationProposalActionsRevertMutation>(revertMutation);
  const [commitAdjudicate, adjudicating] = useApiMutation<CurationProposalActionsAdjudicateMutation>(adjudicateMutation);
  const busy = accepting || rejecting || reverting || adjudicating;
  const isOpen = proposal.proposal_status === 'open';
  const action = proposal.recommended_action;
  const isMerge = action === ACTION_MERGE;
  const isTargeted = TARGETED_ACTIONS.includes(action);
  const isAttribution = action === ACTION_RESOLVE_ATTRIBUTION;
  const needsSelection = isTargeted || isAttribution;
  const count = preview?.count ?? 0;
  const survivor = survivorName ?? t_i18n('the selected entity');
  const close = () => setDialog(null);

  // The rationale is cleared once the decision succeeded: a refused or failed request keeps it for the retry.
  const submit = (rationale: string, onDecided: () => void) => {
    const trimmed = rationale.trim() || null;
    const done = (message: string) => {
      MESSAGING$.notifySuccess(message);
      onDecided();
      close();
    };
    if (dialog === 'accept') {
      const input = {
        rationale: trimmed,
        target_id: isTargeted ? survivorId : null,
        action_payload: isAttribution && survivorId ? JSON.stringify({ keep_actor_id: survivorId }) : null,
      };
      commitAccept({
        variables: { id: proposal.id, input },
        onCompleted: (_, errors) => {
          if (notifyPayloadErrors(errors)) return;
          done(t_i18n('The curation proposal has been applied'));
        },
      });
    } else if (dialog === 'reject') {
      commitReject({
        variables: { id: proposal.id, rationale: trimmed },
        onCompleted: (_, errors) => {
          if (notifyPayloadErrors(errors)) return;
          done(t_i18n('The curation proposal has been rejected'));
        },
      });
    } else if (dialog === 'revert') {
      commitRevert({
        variables: { id: proposal.id },
        onCompleted: (_, errors) => {
          if (notifyPayloadErrors(errors)) return;
          done(t_i18n('The curation proposal has been reverted'));
        },
      });
    }
  };

  const adjudicate = () => {
    commitAdjudicate({
      variables: { id: proposal.id },
      onCompleted: (_, errors) => {
        if (notifyPayloadErrors(errors)) return;
        MESSAGING$.notifySuccess(t_i18n('The OpenCTI Curator has adjudicated the proposal'));
      },
    });
  };

  const acceptTitle = () => {
    if (isMerge) return t_i18n('{count, plural, one {Merge # object into {survivor}} other {Merge # objects into {survivor}}}', { values: { count, survivor } });
    if (isAttribution) return t_i18n('Keep the attribution to {survivor}', { values: { survivor } });
    // The platform's title says what the change does; only the survivor of a merge or an attribution is chosen on screen.
    if (explanation) return translate(explanation.title);
    if (action === ACTION_ADD_ALIASES) {
      // The names the change adds, not the subjects: an alias proposal often has a single subject.
      const names = preview?.aliases.length ?? 0;
      return t_i18n('{count, plural, one {Add # name as an alias of {survivor}} other {Add # names as aliases of {survivor}}}', { values: { count: names, survivor } });
    }
    return t_i18n('{action}: {name}', { values: { action: labels.action(action), name: proposal.name } });
  };
  const acceptLabel = () => {
    if (isMerge) return t_i18n('{count, plural, one {Merge # object} other {Merge # objects}}', { values: { count } });
    if (action === ACTION_ADD_ALIASES) return t_i18n('Add the aliases');
    return t_i18n('Apply');
  };
  const dialogTitles: Record<Exclude<DialogKind, null>, string> = {
    accept: acceptTitle(),
    reject: t_i18n('Reject the curation proposal'),
    revert: t_i18n('Revert the curation proposal'),
  };
  const confirmLabels: Record<Exclude<DialogKind, null>, string> = {
    accept: acceptLabel(),
    reject: t_i18n('Reject'),
    revert: t_i18n('Revert'),
  };

  const acceptPreview = (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1, marginBottom: explanation ? 0 : 2 }} data-testid={explanation ? 'curation-merge-preview' : 'curation-accept-preview'}>
      {isTargeted && preview && (
        <Box component="ul" sx={{ margin: 0, paddingLeft: 2.5 }}>
          {isMerge && (
            <li>{t_i18n('{count, plural, =0 {No relationship moves} one {# relationship moves to {survivor}} other {# relationships move to {survivor}}}', { values: { count: preview.relationships, survivor } })}</li>
          )}
          <li>
            {t_i18n('{count, plural, =0 {No new alias} one {# new alias: {aliases}} other {# new aliases: {aliases}}}', {
              values: { count: preview.aliases.length, aliases: preview.aliases.slice(0, 10).join(', ') },
            })}
          </li>
          {isMerge && (
            <li>{t_i18n('{count, plural, =0 {No external reference moves} one {# external reference moves} other {# external references move}}', { values: { count: preview.externalReferences } })}</li>
          )}
        </Box>
      )}
      {!isTargeted && (
        <Typography variant="body2">
          {t_i18n('Accepting applies the recommended action: {action}.', { values: { action: labels.action(action) } })}
        </Typography>
      )}
      {isMerge && <Typography variant="body2">{t_i18n('You can undo this merge from Data > Curation > Merges.')}</Typography>}
    </Box>
  );

  const primary = () => {
    if (isOpen && proposal.can_apply) {
      return (
        <Button onClick={() => setDialog('accept')} disabled={busy || (needsSelection && !survivorId)} data-testid="curation-proposal-review">
          {isMerge ? t_i18n('Review the merge') : t_i18n('Review the change')}
        </Button>
      );
    }
    if (proposal.merge_record_id) {
      return (
        <Button onClick={() => navigate(`${CURATION_MERGES_PATH}?record=${proposal.merge_record_id}`)}>
          {t_i18n('Open the merge record')}
        </Button>
      );
    }
    return null;
  };

  return (
    <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap', alignItems: 'center' }} data-testid="curation-proposal-actions">
      {isOpen && canDecide && proposal.adjudicable && adjudicationAvailable && (
        <EETooltip title={t_i18n('Ask the OpenCTI Curator agent of XTM One to adjudicate this proposal')}>
          <span>
            <Button variant="secondary" intent="ai" onClick={adjudicate} disabled={busy || !isEnterpriseEdition}>
              {t_i18n('Ask the Curator')}
            </Button>
          </span>
        </EETooltip>
      )}
      {isOpen && canDecide && (
        <Button variant="secondary" onClick={() => setDialog('reject')} disabled={busy}>
          {t_i18n('Reject')}
        </Button>
      )}
      {proposal.can_revert && (
        <Button variant="secondary" intent="destructive" onClick={() => setDialog('revert')} disabled={busy}>
          {t_i18n('Revert')}
        </Button>
      )}
      {primary()}
      {isOpen && proposal.can_apply && isAttribution && !survivorId && (
        <Typography variant="body2" color="text.secondary">
          {t_i18n('Choose the attribution to keep in the comparison below')}
        </Typography>
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
          submit(values.rationale, () => resetForm());
        }}
      >
        {({ submitForm, resetForm }) => {
          const cancel = () => {
            resetForm();
            close();
          };
          return (
            <Dialog
              open={dialog !== null}
              onClose={cancel}
              title={dialog ? dialogTitles[dialog] : ''}
              size={dialog === 'accept' && explanation ? 'large' : 'medium'}
            >
              {dialog === 'accept' && explanation && (
                <Box sx={{ marginBottom: 2 }} data-testid="curation-accept-preview">
                  <CurationProposalExplanation
                    explanation={explanation}
                    changes={isMerge ? acceptPreview : undefined}
                    chosen={isAttribution ? survivorName : null}
                  />
                </Box>
              )}
              {dialog === 'accept' && !explanation && acceptPreview}
              {dialog === 'revert' && (
                <Typography variant="body2" sx={{ marginBottom: 2 }}>
                  {t_i18n('The change applied by this proposal is undone; merged entities are restored from their snapshots.')}
                </Typography>
              )}
              {dialog === 'reject' && (
                <Typography variant="body2" sx={{ marginBottom: 2 }}>
                  {explanation
                    ? `${translate(explanation.on_reject)} ${t_i18n('Your reason helps calibrate the next proposals.')}`
                    : t_i18n('The proposal is closed and the same subjects are not proposed again for the same reason. Your reason helps calibrate the next proposals.')}
                </Typography>
              )}
              {dialog !== 'revert' && (
                <Form>
                  <Field
                    component={TextareaField}
                    name="rationale"
                    label={dialog === 'reject' ? t_i18n('Reason (optional)') : t_i18n('Rationale (optional)')}
                    rows={3}
                  />
                </Form>
              )}
              <DialogActions>
                <Button variant="secondary" onClick={cancel} disabled={busy}>
                  {t_i18n('Cancel')}
                </Button>
                <Button
                  onClick={submitForm}
                  disabled={busy}
                  intent={dialog === 'revert' ? 'destructive' : 'default'}
                  data-testid="curation-proposal-confirm"
                >
                  {dialog ? confirmLabels[dialog] : ''}
                </Button>
              </DialogActions>
            </Dialog>
          );
        }}
      </Formik>
    </Box>
  );
};

export default CurationProposalActions;
