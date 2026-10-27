import React, { Suspense } from 'react';
import { graphql } from 'react-relay';
import { Link } from 'react-router';
import { Text } from '@filigran/design-system';
import Box from '@mui/material/Box';
import Button from '@common/button/Button';
import Drawer from '@components/common/drawer/Drawer';
import { useFormatter } from '../../../../components/i18n';
import ItemIcon from '../../../../components/ItemIcon';
import IrEntityPreview from './IrEntityPreview';
import IrScoreHistory from './IrScoreHistory';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { criterionName, explanationText, type IrCriterionRef, type IrExplanationData, ScoreBar, StatusChip } from './IrOutputCommon';
import type { IrMatchDrawerStatusMutation } from './__generated__/IrMatchDrawerStatusMutation.graphql';

const statusMutation = graphql`
  mutation IrMatchDrawerStatusMutation($id: ID!, $status: IrMatchDecisionStatus!) {
    intelligenceRequirementMatchStatusUpdate(id: $id, status: $status) {
      id
      match_status
    }
  }
`;

export interface IrMatchData {
  readonly id: string;
  readonly match_status: string;
  readonly match_score: number;
  readonly match_excluded: boolean;
  readonly match_entity_type: string;
  readonly match_entity_id: string;
  readonly match_last_fact_at?: string | null;
  readonly entity?: { readonly representative: { readonly main: string } } | null;
  readonly match_explanations: readonly IrExplanationData[];
  readonly match_score_breakdown: readonly {
    readonly name: string;
    readonly points: number;
    readonly hit: boolean;
    readonly reason?: string | null;
    readonly kind?: string | null; // rule (relevance) or condition (scope)
    readonly criterion_id?: string | null;
  }[];
}

// Decision on an entity of the requirement (accept, reject, remove): also closes its open inbox items
export const useMatchDecision = (onDone: () => void) => {
  const [commit, inFlight] = useApiMutation<IrMatchDrawerStatusMutation>(statusMutation);
  const decide = (matchId: string, status: 'accepted' | 'rejected' | 'removed') => {
    commit({ variables: { id: matchId, status }, onCompleted: onDone });
  };
  return { decide, inFlight };
};

interface IrMatchDetailsProps {
  irId: string;
  match: IrMatchData;
  criteria: readonly IrCriterionRef[];
  onDecided: () => void;
  embedded?: boolean; // the mailbox reading pane has its own header (type, status, score, link) and action bar
}

// What an entity of the requirement is and why it is there: entity, proofs, conditions of the scope, score, history
export const IrMatchDetails = ({ irId, match, criteria, onDecided, embedded }: IrMatchDetailsProps) => {
  const { t_i18n, fldt } = useFormatter();
  const { decide: decideMatch, inFlight } = useMatchDecision(onDecided);
  const decide = (status: 'accepted' | 'rejected' | 'removed') => decideMatch(match.id, status);
  const conditions = match.match_score_breakdown.filter((o) => o.kind === 'condition');
  const rules = match.match_score_breakdown.filter((o) => o.kind !== 'condition');
  const applicable = rules.filter((o) => o.reason !== 'not applicable');
  const notApplicable = rules.length - applicable.length;
  const conditionCriteria = Array.from(new Set(conditions.map((o) => o.criterion_id ?? '')));
  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
      {!embedded && (
        <Box sx={{ display: 'flex', gap: 1.5, alignItems: 'center' }}>
          <ItemIcon type={match.match_entity_type} size="small" />
          <Text as="span" variant="content-caption">{t_i18n(`entity_${match.match_entity_type}`)}</Text>
          <StatusChip status={match.match_status} excluded={match.match_excluded} t={t_i18n} />
          <ScoreBar score={match.match_score} excluded={match.match_excluded} />
          <Box sx={{ flex: 1 }} />
          <Link to={`/dashboard/id/${match.match_entity_id}`} target="_blank" rel="noopener noreferrer">{t_i18n('Open entity')}</Link>
        </Box>
      )}
      <Box>
        <Text as="div" variant="content-compact-bold" style={{ marginBottom: 8 }}>{t_i18n('Entity')}</Text>
        <IrEntityPreview entityId={match.match_entity_id} />
      </Box>
      <Box>
        <Text as="div" variant="content-compact-bold" style={{ marginBottom: 8 }}>{t_i18n('Why it is in this requirement (scope)')}</Text>
        {match.match_explanations.map((e, i) => (
          <Box key={i} sx={{ border: '1px solid', borderColor: 'divider', borderRadius: 1, p: 1.5, mb: 1 }}>
            <Text as="div" variant="content-compact-medium">{criterionName(criteria, e.criterion_id)}</Text>
            <Text as="div" variant="content-caption" style={{ opacity: 0.8 }}>{explanationText(e)}</Text>
          </Box>
        ))}
      </Box>
      {conditions.length > 0 && (
        <Box>
          <Text as="div" variant="content-compact-bold" style={{ marginBottom: 8 }}>
            {match.match_excluded ? t_i18n('Not eligible: the conditions of the scope are not met') : t_i18n('Conditions of the scope')}
          </Text>
          {conditionCriteria.map((criterionId) => (
            <Box key={criterionId} sx={{ border: '1px solid', borderColor: 'divider', borderRadius: 1, p: 1.5, mb: 1 }}>
              <Text as="div" variant="content-compact-medium" style={{ marginBottom: 4 }}>{criterionName(criteria, criterionId)}</Text>
              {conditions.filter((o) => (o.criterion_id ?? '') === criterionId).map((o, i) => (
                <Text key={i} as="div" variant="content-compact" style={{ color: o.hit ? undefined : '#ff8a80' }}>{`${o.hit ? '✓' : '✗'} ${o.name}`}</Text>
              ))}
            </Box>
          ))}
        </Box>
      )}
      <Box>
        <Text as="div" variant="content-compact-bold" style={{ marginBottom: 8 }}>{t_i18n('Score (relevance rules)')}</Text>
        {applicable.map((o, i) => (
          <Box key={i} sx={{ display: 'grid', gridTemplateColumns: '1fr 60px', py: 0.75, borderBottom: '1px solid', borderColor: 'divider', opacity: o.hit ? 1 : 0.6 }}>
            <Box>
              <Text as="div" variant="content-compact">{`${o.hit ? '✓' : '·'} ${o.name}`}</Text>
              {!o.hit && o.reason && (
                <Text as="div" variant="content-caption" style={{ opacity: 0.8 }}>{t_i18n(o.reason)}</Text>
              )}
            </Box>
            <Text as="span" variant="content-compact-bold" style={{ textAlign: 'right' }}>{o.hit ? `${o.points > 0 ? '+' : ''}${o.points}` : '0'}</Text>
          </Box>
        ))}
        <Box sx={{ display: 'grid', gridTemplateColumns: '1fr 60px', py: 1 }}>
          <Text as="span" variant="content-compact-bold">{match.match_excluded ? t_i18n('Not eligible') : t_i18n('Score (sum, capped 0–100)')}</Text>
          <Text as="span" variant="content-compact-bold" style={{ textAlign: 'right' }}>{match.match_excluded ? '—' : match.match_score}</Text>
        </Box>
        {notApplicable > 0 && <Text as="div" variant="content-caption" style={{ opacity: 0.7 }}>{`${notApplicable} ${t_i18n('rules not applicable to this entity')}`}</Text>}
      </Box>
      <Box>
        <Text as="div" variant="content-compact-bold" style={{ marginBottom: 8 }}>{t_i18n('History')}</Text>
        <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
          <IrScoreHistory matchId={match.id} irId={irId} />
        </Suspense>
      </Box>
      {match.match_last_fact_at && <Text as="div" variant="content-caption">{`${t_i18n('Last fact')}: ${fldt(match.match_last_fact_at)}`}</Text>}
      {!embedded && (
        <Box sx={{ display: 'flex', gap: 1 }}>
          {match.match_status === 'proposed' && (
            <>
              <Button onClick={() => decide('accepted')} disabled={inFlight}>{t_i18n('Accept into the requirement')}</Button>
              <Button variant="secondary" onClick={() => decide('rejected')} disabled={inFlight}>{t_i18n('Reject')}</Button>
            </>
          )}
          {(match.match_status === 'auto' || match.match_status === 'accepted') && (
            <Button variant="secondary" onClick={() => decide('removed')} disabled={inFlight}>{t_i18n('Remove from the requirement')}</Button>
          )}
        </Box>
      )}
    </Box>
  );
};

interface IrMatchDrawerProps {
  irId: string;
  match: IrMatchData | null;
  criteria: readonly IrCriterionRef[];
  onClose: () => void;
  onChanged: () => void;
}

const IrMatchDrawer = ({ irId, match, criteria, onClose, onChanged }: IrMatchDrawerProps) => {
  const name = match?.entity?.representative.main ?? match?.match_entity_id ?? '';
  return (
    <Drawer open={!!match} onClose={onClose} title={name} size="large">
      {match ? (
        <IrMatchDetails
          irId={irId}
          match={match}
          criteria={criteria}
          onDecided={() => {
            onChanged();
            onClose();
          }}
        />
      ) : <div />}
    </Drawer>
  );
};

export default IrMatchDrawer;
