import React, { useState } from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import { Paper, Text } from '@filigran/design-system';
import Box from '@mui/material/Box';
import Button from '@common/button/Button';
import { useFormatter } from '../../../../components/i18n';
import ItemIcon from '../../../../components/ItemIcon';
import { criterionName, explanationText, IN_STATUSES, ScoreBar, StatusChip } from './IrOutputCommon';
import IrMatchDrawer, { type IrMatchData } from './IrMatchDrawer';
import type { IrEntitiesQuery } from './__generated__/IrEntitiesQuery.graphql';

// ① Entities of the requirement: entry (criterion, proof, status) and score (relevance rules).

export const irEntitiesQuery = graphql`
  query IrEntitiesQuery($id: ID!) {
    intelligenceRequirement(id: $id) {
      id
      ir_scope_criteria { id name kind }
    }
    intelligenceRequirementMatches(id: $id, first: 500, orderBy: match_score, orderMode: desc) {
      edges {
        node {
          id
          match_status
          match_score
          match_excluded
          match_entity_type
          match_entity_id
          match_criteria_ids
          match_last_fact_at
          entity { ... on StixCoreObject { representative { main } } }
          match_explanations {
            criterion_id
            kind
            relationship_type
            direction
            keyword
            field
            anchor { representative { main } }
            container { representative { main } }
          }
          match_score_breakdown { name points hit reason }
        }
      }
    }
  }
`;

type Filter = 'in' | 'proposed' | 'excluded' | 'closed';

const IrEntities = ({ irId }: { irId: string }) => {
  const { t_i18n, nsdt } = useFormatter();
  const [fetchKey, setFetchKey] = useState(0);
  const [filter, setFilter] = useState<Filter>('in');
  const [type, setType] = useState<string | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const data = useLazyLoadQuery<IrEntitiesQuery>(irEntitiesQuery, { id: irId }, { fetchPolicy: 'network-only', fetchKey });
  const criteria = data.intelligenceRequirement?.ir_scope_criteria ?? [];
  const matches = (data.intelligenceRequirementMatches?.edges ?? []).map((e) => e.node);
  const counts = {
    in: matches.filter((m) => IN_STATUSES.includes(m.match_status) && !m.match_excluded).length,
    proposed: matches.filter((m) => m.match_status === 'proposed').length,
    excluded: matches.filter((m) => IN_STATUSES.includes(m.match_status) && m.match_excluded).length,
    closed: matches.filter((m) => m.match_status === 'rejected' || m.match_status === 'removed').length,
  };
  const visible = matches.filter((m) => {
    if (type && m.match_entity_type !== type) return false;
    if (filter === 'in') return IN_STATUSES.includes(m.match_status) && !m.match_excluded;
    if (filter === 'proposed') return m.match_status === 'proposed';
    if (filter === 'excluded') return IN_STATUSES.includes(m.match_status) && m.match_excluded;
    return m.match_status === 'rejected' || m.match_status === 'removed';
  });
  const types = Array.from(new Set(matches.map((m) => m.match_entity_type)));
  const selectedMatch = matches.find((m) => m.id === selected) ?? null;
  const filterButton = (value: Filter, label: string) => (
    <Button key={value} size="small" variant={filter === value ? 'primary' : 'secondary'} onClick={() => setFilter(value)}>{`${t_i18n(label)} (${counts[value]})`}</Button>
  );
  return (
    <>
      <Box sx={{ display: 'flex', gap: 1, mb: 2, flexWrap: 'wrap', alignItems: 'center' }}>
        {filterButton('in', 'In the requirement')}
        {filterButton('proposed', 'Proposed')}
        {filterButton('excluded', 'Excluded by a required rule')}
        {filterButton('closed', 'Rejected or removed')}
        <Box sx={{ flex: 1 }} />
        <Button size="small" variant={type === null ? 'primary' : 'tertiary'} onClick={() => setType(null)}>{t_i18n('All types')}</Button>
        {types.map((tp) => (
          <Button key={tp} size="small" variant={type === tp ? 'primary' : 'tertiary'} onClick={() => setType(tp)}>{t_i18n(`entity_${tp}`)}</Button>
        ))}
      </Box>
      <Paper padding={0}>
        <Box sx={{ display: 'grid', gridTemplateColumns: '1.2fr 1.6fr 1.6fr 120px 110px', gap: 2, px: 3, py: 1, borderBottom: '1px solid', borderColor: 'divider', opacity: 0.7 }}>
          <Text as="span" variant="content-caption">{t_i18n('Entity')}</Text>
          <Text as="span" variant="content-caption">{t_i18n('Entry · criterion and proof')}</Text>
          <Text as="span" variant="content-caption">{t_i18n('Main scoring reasons')}</Text>
          <Text as="span" variant="content-caption">{t_i18n('Score')}</Text>
          <Text as="span" variant="content-caption">{t_i18n('Last fact')}</Text>
        </Box>
        {visible.length === 0 && <Box sx={{ p: 3 }}><Text as="span" variant="content-base">{t_i18n('No entity.')}</Text></Box>}
        {visible.map((m) => {
          const reasons = m.match_score_breakdown.filter((o) => o.hit && o.points !== 0).sort((a, b) => Math.abs(b.points) - Math.abs(a.points)).slice(0, 3);
          const required = m.match_score_breakdown.find((o) => o.reason?.startsWith('required'));
          const proof = m.match_explanations[0];
          return (
            <Box
              key={m.id}
              onClick={() => setSelected(m.id)}
              sx={{ display: 'grid', gridTemplateColumns: '1.2fr 1.6fr 1.6fr 120px 110px', gap: 2, alignItems: 'center', px: 3, py: 1.25, cursor: 'pointer', borderBottom: '1px solid', borderColor: 'divider', '&:hover': { bgcolor: 'action.hover' } }}
            >
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
                <ItemIcon type={m.match_entity_type} size="small" />
                <Box>
                  <Text as="div" variant="content-compact-medium">{m.entity?.representative.main ?? m.match_entity_id}</Text>
                  <Text as="div" variant="content-caption" style={{ opacity: 0.7 }}>{t_i18n(`entity_${m.match_entity_type}`)}</Text>
                </Box>
              </Box>
              <Box sx={{ display: 'flex', gap: 1, alignItems: 'center', flexWrap: 'wrap' }}>
                <StatusChip status={m.match_status} t={t_i18n} />
                <Text as="span" variant="content-caption">
                  {proof ? `${criterionName(criteria, proof.criterion_id)} · ${explanationText(proof)}` : ''}
                  {m.match_explanations.length > 1 ? ` (+${m.match_explanations.length - 1})` : ''}
                </Text>
              </Box>
              <Box sx={{ display: 'flex', gap: 0.75, flexWrap: 'wrap' }}>
                {m.match_excluded && required && <Text as="span" variant="content-caption" style={{ color: '#ff8a80' }}>{`${t_i18n('Excluded')} · ${required.name}`}</Text>}
                {!m.match_excluded && reasons.map((o) => (
                  <Box key={o.name} component="span" sx={{ fontSize: 11, border: '1px solid', borderColor: 'divider', borderRadius: 0.5, px: 0.75 }}>{`${o.name} ${o.points > 0 ? '+' : ''}${o.points}`}</Box>
                ))}
              </Box>
              <ScoreBar score={m.match_score} excluded={m.match_excluded} />
              <Text as="span" variant="content-caption">{m.match_last_fact_at ? nsdt(m.match_last_fact_at) : '-'}</Text>
            </Box>
          );
        })}
      </Paper>
      <IrMatchDrawer
        match={selectedMatch as IrMatchData | null}
        criteria={criteria}
        onClose={() => setSelected(null)}
        onChanged={() => setFetchKey((k) => k + 1)}
      />
    </>
  );
};

export default IrEntities;
