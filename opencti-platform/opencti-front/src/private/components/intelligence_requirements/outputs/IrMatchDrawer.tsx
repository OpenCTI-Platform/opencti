import React from 'react';
import { graphql } from 'react-relay';
import { Link } from 'react-router';
import { Text } from '@filigran/design-system';
import Box from '@mui/material/Box';
import Button from '@common/button/Button';
import Drawer from '@components/common/drawer/Drawer';
import { useFormatter } from '../../../../components/i18n';
import ItemIcon from '../../../../components/ItemIcon';
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
  readonly match_score_breakdown: readonly { readonly name: string; readonly points: number; readonly hit: boolean; readonly reason?: string | null }[];
}

interface IrMatchDrawerProps {
  match: IrMatchData | null;
  criteria: readonly IrCriterionRef[];
  onClose: () => void;
  onChanged: () => void;
}

const IrMatchDrawer = ({ match, criteria, onClose, onChanged }: IrMatchDrawerProps) => {
  const { t_i18n, fldt } = useFormatter();
  const [commit, inFlight] = useApiMutation<IrMatchDrawerStatusMutation>(statusMutation);
  const decide = (status: 'accepted' | 'rejected' | 'removed') => {
    if (!match) return;
    const onCompleted = () => {
      onChanged();
      onClose();
    };
    commit({ variables: { id: match.id, status }, onCompleted });
  };
  const name = match?.entity?.representative.main ?? match?.match_entity_id ?? '';
  const applicable = (match?.match_score_breakdown ?? []).filter((o) => o.reason !== 'not applicable');
  const notApplicable = (match?.match_score_breakdown ?? []).length - applicable.length;
  return (
    <Drawer open={!!match} onClose={onClose} title={name} size="medium">
      {match ? (
        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
          <Box sx={{ display: 'flex', gap: 1.5, alignItems: 'center' }}>
            <ItemIcon type={match.match_entity_type} size="small" />
            <Text as="span" variant="content-caption">{t_i18n(`entity_${match.match_entity_type}`)}</Text>
            <StatusChip status={match.match_status} excluded={match.match_excluded} t={t_i18n} />
            <ScoreBar score={match.match_score} excluded={match.match_excluded} />
            <Box sx={{ flex: 1 }} />
            <Link to={`/dashboard/id/${match.match_entity_id}`}>{t_i18n('Open entity')}</Link>
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
          <Box>
            <Text as="div" variant="content-compact-bold" style={{ marginBottom: 8 }}>{t_i18n('Score (relevance rules)')}</Text>
            {applicable.map((o, i) => (
              <Box key={i} sx={{ display: 'grid', gridTemplateColumns: '1fr 60px', py: 0.75, borderBottom: '1px solid', borderColor: 'divider', opacity: o.hit ? 1 : 0.6 }}>
                <Box>
                  <Text as="div" variant="content-compact">{`${o.hit ? '✓' : '·'} ${o.name}`}</Text>
                  {!o.hit && o.reason && (
                    <Text as="div" variant="content-caption" style={{ color: o.reason.startsWith('required') ? '#ff8a80' : undefined }}>{t_i18n(o.reason)}</Text>
                  )}
                </Box>
                <Text as="span" variant="content-compact-bold" style={{ textAlign: 'right' }}>{o.hit ? `${o.points > 0 ? '+' : ''}${o.points}` : '0'}</Text>
              </Box>
            ))}
            <Box sx={{ display: 'grid', gridTemplateColumns: '1fr 60px', py: 1 }}>
              <Text as="span" variant="content-compact-bold">{match.match_excluded ? t_i18n('Excluded by a required rule') : t_i18n('Score (sum, capped 0–100)')}</Text>
              <Text as="span" variant="content-compact-bold" style={{ textAlign: 'right' }}>{match.match_excluded ? '—' : match.match_score}</Text>
            </Box>
            {notApplicable > 0 && <Text as="div" variant="content-caption" style={{ opacity: 0.7 }}>{`${notApplicable} ${t_i18n('rules not applicable to this entity')}`}</Text>}
          </Box>
          {match.match_last_fact_at && <Text as="div" variant="content-caption">{`${t_i18n('Last fact')}: ${fldt(match.match_last_fact_at)}`}</Text>}
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
        </Box>
      ) : <div />}
    </Drawer>
  );
};

export default IrMatchDrawer;
