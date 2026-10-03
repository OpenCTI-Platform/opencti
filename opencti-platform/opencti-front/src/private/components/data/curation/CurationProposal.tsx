import { useState } from 'react';
import { graphql, useFragment, useLazyLoadQuery } from 'react-relay';
import { Link, useParams } from 'react-router';
import Box from '@mui/material/Box';
import Typography from '@mui/material/Typography';
import { useTheme } from '@mui/styles';
import Card from '@common/card/Card';
import Label from '@common/label/Label';
import Tag from '@common/tag/Tag';
import { useFormatter } from '../../../../components/i18n';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import type { Theme } from '../../../../components/Theme';
import useConnectedDocumentModifier from '../../../../utils/hooks/useConnectedDocumentModifier';
import CurationProposalActions from './CurationProposalActions';
import CurationProposalCompare from './CurationProposalCompare';
import CurationProposalEvidence from './CurationProposalEvidence';
import CurationConfidence from './CurationConfidence';
import useCurationLabels, { CURATION_MERGES_PATH, parseJsonObject } from './curationUtils';
import { CurationProposalQuery } from './__generated__/CurationProposalQuery.graphql';
import { CurationProposal_proposal$key } from './__generated__/CurationProposal_proposal.graphql';

const proposalDetailsFragment = graphql`
  fragment CurationProposal_proposal on CurationProposal {
    id
    name
    proposal_kind
    proposal_status
    confidence_score
    in_ambiguous_band
    detector
    recommended_action
    action_payload
    target_id
    subject_ids
    subject_names
    adjudication {
      decision
      rationale
      agent_slug
      model
      adjudicated_at
      applied
      verified
    }
    adjudication_requested_at
    policy {
      id
      name
    }
    decided_at
    decidedBy {
      id
      name
    }
    decision_rationale
    merge_record_id
    applied_patch
    can_apply
    can_revert
    adjudicable
    created_at
    updated_at
    ...CurationProposalCompare_proposal
    ...CurationProposalEvidence_proposal
  }
`;

const curationProposalQuery = graphql`
  query CurationProposalQuery($id: ID!) {
    curationProposal(id: $id) {
      id
      ...CurationProposal_proposal
    }
    curationSettings {
      adjudication_available
      adjudication_enabled
    }
  }
`;

const PAYLOAD_HIDDEN_KEYS = ['element_id', 'relationship_id'];

const CurationProposalDetails = ({ data, adjudicationAvailable }: { data: CurationProposal_proposal$key; adjudicationAvailable: boolean }) => {
  const theme = useTheme<Theme>();
  const { t_i18n, fldt } = useFormatter();
  const labels = useCurationLabels();
  const proposal = useFragment(proposalDetailsFragment, data);
  const payload = parseJsonObject(proposal.action_payload);
  const isAttribution = proposal.recommended_action === 'resolve_attribution';
  const attributionActorIds = isAttribution && Array.isArray(payload?.relationships)
    ? (payload.relationships as Array<{ actor_id?: string }>).map((relation) => relation.actor_id).filter((id): id is string => !!id)
    : [];
  const proposedSurvivorId = isAttribution ? null : (proposal.target_id ?? proposal.subject_ids[0] ?? null);
  // The analyst's pick holds until the proposal target changes (an adjudication), then the new target is proposed.
  const [selection, setSelection] = useState<{ survivorId: string | null; forTargetId: string | null } | null>(null);
  const survivorId = selection && selection.forTargetId === (proposal.target_id ?? null) ? selection.survivorId : proposedSurvivorId;
  const setSurvivorId = (id: string | null) => setSelection({ survivorId: id, forTargetId: proposal.target_id ?? null });
  const isOpen = proposal.proposal_status === 'open';
  const isTargeted = isAttribution || ['merge', 'add_aliases'].includes(proposal.recommended_action);
  const survivorIndex = survivorId ? proposal.subject_ids.indexOf(survivorId) : -1;
  const survivorName = survivorIndex >= 0 ? proposal.subject_names[survivorIndex] ?? null : null;
  const payloadEntries = payload ? Object.entries(payload).filter(([key]) => !PAYLOAD_HIDDEN_KEYS.includes(key)) : [];

  return (
    <>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, marginBottom: 2, flexWrap: 'wrap' }}>
        <Typography variant="h1" sx={{ margin: 0 }} data-testid="curation-proposal-title">{proposal.name}</Typography>
        <Tag label={labels.kind(proposal.proposal_kind)} />
        <Tag label={labels.status(proposal.proposal_status)} color={labels.statusColor(proposal.proposal_status)} />
        <Box sx={{ flex: 1 }} />
        <CurationProposalActions
          proposal={proposal}
          survivorId={survivorId}
          survivorName={survivorName}
          adjudicationAvailable={adjudicationAvailable}
        />
      </Box>
      <Box sx={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 2, marginBottom: 2 }}>
        <Card title={t_i18n('Recommendation')}>
          <Box sx={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 2 }}>
            <div>
              <Label>{t_i18n('Recommended action')}</Label>
              <Typography variant="body2">{labels.action(proposal.recommended_action)}</Typography>
            </div>
            <div>
              <Label>{t_i18n('Confidence')}</Label>
              <CurationConfidence value={proposal.confidence_score} ambiguous={proposal.in_ambiguous_band} />
            </div>
            <div>
              <Label>{t_i18n('Detector')}</Label>
              <Typography variant="body2">{labels.detector(proposal.detector)}</Typography>
            </div>
            <div>
              <Label>{t_i18n('Detection date')}</Label>
              <Typography variant="body2">{fldt(proposal.created_at)}</Typography>
            </div>
            {payloadEntries.length > 0 && (
              <Box sx={{ gridColumn: '1 / -1' }}>
                <Label>{t_i18n('Proposed change')}</Label>
                <Box component="dl" sx={{ margin: 0, fontSize: 13 }} data-testid="curation-proposed-change">
                  {payloadEntries.map(([key, value]) => (
                    <div key={key}>
                      <Box component="dt" sx={{ display: 'inline', fontWeight: 600 }}>{key}: </Box>
                      <Box component="dd" sx={{ display: 'inline', margin: 0 }}>
                        {typeof value === 'object' ? JSON.stringify(value) : String(value)}
                      </Box>
                    </div>
                  ))}
                </Box>
              </Box>
            )}
          </Box>
        </Card>
        <Card title={t_i18n('Decision')}>
          {isOpen ? (
            <Typography variant="body2" color={theme.palette.text.light}>
              {t_i18n('This proposal waits for a decision')}
            </Typography>
          ) : (
            <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
              <Typography variant="body2">
                {labels.status(proposal.proposal_status)}
                {proposal.decided_at && ` - ${fldt(proposal.decided_at)}`}
              </Typography>
              {proposal.decidedBy && <Typography variant="body2">{t_i18n('By')} {proposal.decidedBy.name}</Typography>}
              {proposal.policy && <Typography variant="body2">{t_i18n('Curation policy')}: {proposal.policy.name}</Typography>}
              {proposal.decision_rationale && <Typography variant="body2">{proposal.decision_rationale}</Typography>}
              {proposal.merge_record_id && (
                <Link to={`${CURATION_MERGES_PATH}?record=${proposal.merge_record_id}`}>{t_i18n('Open the merge record')}</Link>
              )}
            </Box>
          )}
        </Card>
      </Box>
      <Box sx={{ marginBottom: 2 }}>
        <CurationProposalCompare
          data={proposal}
          survivorId={isTargeted ? survivorId : null}
          onSelectSurvivor={isOpen && isTargeted ? setSurvivorId : undefined}
          selectableIds={isAttribution ? attributionActorIds : undefined}
          selectedLabel={isAttribution ? t_i18n('Attribution kept') : undefined}
        />
      </Box>
      <Box sx={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 2 }}>
        <CurationProposalEvidence data={proposal} />
        <Card title={t_i18n('Adjudication')}>
          {proposal.adjudication ? (
            <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }} data-testid="curation-adjudication">
              <Box sx={{ display: 'flex', gap: 1, alignItems: 'center' }}>
                <Tag label={labels.decision(proposal.adjudication.decision)} />
                {proposal.adjudication.applied && <Tag label={t_i18n('Applied')} color={theme.palette.success.main} />}
                <Tag label={proposal.adjudication.verified ? t_i18n('Requested by OpenCTI') : t_i18n('Recorded through the API')} />
              </Box>
              <Typography variant="body2">{proposal.adjudication.rationale}</Typography>
              <Typography variant="caption" color={theme.palette.text.light}>
                {[proposal.adjudication.agent_slug, proposal.adjudication.model, fldt(proposal.adjudication.adjudicated_at)].filter(Boolean).join(' - ')}
              </Typography>
            </Box>
          ) : (
            <Typography variant="body2" color={theme.palette.text.light}>
              {proposal.adjudicable
                ? t_i18n('This proposal is in the ambiguous band: the OpenCTI Curator can adjudicate it (Enterprise Edition).')
                : t_i18n('Only duplicate proposals (merge or alias) in the ambiguous band are adjudicated.')}
              {proposal.adjudication_requested_at && ` ${t_i18n('Last request')}: ${fldt(proposal.adjudication_requested_at)}`}
            </Typography>
          )}
        </Card>
      </Box>
    </>
  );
};

const CurationProposal = () => {
  const { t_i18n } = useFormatter();
  const { proposalId } = useParams() as { proposalId: string };
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Curation proposal | Curation | Data'));
  const data = useLazyLoadQuery<CurationProposalQuery>(curationProposalQuery, { id: proposalId }, { fetchPolicy: 'store-and-network' });
  if (!data.curationProposal) {
    return <ErrorNotFound />;
  }
  return (
    <div data-testid="curation-proposal-page">
      <CurationProposalDetails
        data={data.curationProposal}
        adjudicationAvailable={data.curationSettings.adjudication_available && data.curationSettings.adjudication_enabled}
      />
    </div>
  );
};

export default CurationProposal;
