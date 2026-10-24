import React, { useState } from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import { Link } from 'react-router';
import { Chip, Paper, Text } from '@filigran/design-system';
import Box from '@mui/material/Box';
import { useFormatter } from '../../../../components/i18n';
import ItemIcon from '../../../../components/ItemIcon';
import { criterionName, IN_STATUSES, ScoreBar } from './IrOutputCommon';
import { IrInboxItem } from './IrInbox';
import IrMatchDrawer, { type IrMatchData } from './IrMatchDrawer';
import type { IrOverviewQuery } from './__generated__/IrOverviewQuery.graphql';

// Overview: the synthesis of the outputs (inbox to review, top entities, key intelligence questions).

const overviewQuery = graphql`
  query IrOverviewQuery($id: ID!) {
    intelligenceRequirement(id: $id) {
      id
      ir_thresholds
      ir_kiqs { id text criteria_ids }
      ir_subject_groups { id name }
      ir_scope_criteria { id name kind mode from_group_ids from_in_requirement }
    }
    intelligenceRequirementMatches(id: $id, first: 500, statuses: [auto, accepted, proposed], orderBy: match_score, orderMode: desc) {
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
            anchor_id
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
    intelligenceRequirementItems(id: $id, first: 50, statuses: [open]) {
      edges {
        node {
          id
          item_kind
          item_status
          item_title
          item_result
          item_entity_type
          created_at
          item_data { criterion_id from_score to_score reasons }
          match {
            id
            match_score
            match_excluded
            entity { ... on StixCoreObject { representative { main } } }
            match_explanations {
              criterion_id
              kind
              anchor_id
              relationship_type
              direction
              keyword
              field
              anchor { representative { main } }
              container { representative { main } }
            }
          }
        }
      }
    }
  }
`;

const Kpi = ({ label, value, detail }: { label: string; value: string | number; detail?: string }) => (
  <Paper padding={16}>
    <Text as="div" variant="content-caption" style={{ opacity: 0.8 }}>{label}</Text>
    <Text as="div" variant="title-xl">{String(value)}</Text>
    {detail && <Text as="div" variant="content-caption" style={{ opacity: 0.7 }}>{detail}</Text>}
  </Paper>
);

const IrOverview = ({ irId }: { irId: string }) => {
  const { t_i18n } = useFormatter();
  const [fetchKey, setFetchKey] = useState(0);
  const [selected, setSelected] = useState<string | null>(null);
  const data = useLazyLoadQuery<IrOverviewQuery>(overviewQuery, { id: irId }, { fetchPolicy: 'network-only', fetchKey });
  const ir = data.intelligenceRequirement;
  const criteria = ir?.ir_scope_criteria ?? [];
  const groups = ir?.ir_subject_groups ?? [];
  const matches = (data.intelligenceRequirementMatches?.edges ?? []).map((e) => e.node);
  const inRequirement = matches.filter((m) => IN_STATUSES.includes(m.match_status) && !m.match_excluded);
  const proposed = matches.filter((m) => m.match_status === 'proposed');
  const excluded = matches.filter((m) => IN_STATUSES.includes(m.match_status) && m.match_excluded);
  const items = (data.intelligenceRequirementItems?.edges ?? []).map((e) => e.node);
  const topThreshold = Math.max(...(ir?.ir_thresholds ?? [80]));
  const high = inRequirement.filter((m) => m.match_score >= topThreshold);
  const kiqs = (ir?.ir_kiqs ?? []).map((k) => ({ ...k, answered: inRequirement.some((m) => m.match_criteria_ids.some((c) => k.criteria_ids.includes(c))) }));
  return (
    <>
      <Box sx={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 2, mb: 2 }}>
        <Kpi label={t_i18n('Entities in the requirement')} value={inRequirement.length} detail={`${proposed.length} ${t_i18n('proposed')} · ${excluded.length} ${t_i18n('excluded')}`} />
        <Kpi label={t_i18n('Inbox · to review')} value={items.length} detail={`${items.filter((i) => i.item_kind === 'proposed').length} ${t_i18n('proposed to accept')}`} />
        <Kpi label={`${t_i18n('Score')} ≥ ${topThreshold}`} value={high.length} detail={t_i18n('high-priority entities')} />
        <Kpi label={t_i18n('KIQs answered')} value={`${kiqs.filter((k) => k.answered).length}/${kiqs.length}`} />
      </Box>
      <Box sx={{ display: 'grid', gridTemplateColumns: '1.6fr 1fr', gap: 2 }}>
        <Paper padding={16}>
          <Box sx={{ display: 'flex', mb: 1.5 }}>
            <Text as="span" variant="title-sm">{t_i18n('Inbox')}</Text>
            <Box sx={{ flex: 1 }} />
            <Link to={`/dashboard/intelligence_requirements/${irId}/inbox`}>{t_i18n('Open inbox')}</Link>
          </Box>
          {items.length === 0 && <Text as="span" variant="content-base">{t_i18n('Nothing to review.')}</Text>}
          {items.slice(0, 6).map((item) => (
            <IrInboxItem key={item.id} item={item} criteria={criteria} groups={groups} matches={matches} onDetails={setSelected} compact />
          ))}
        </Paper>
        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
          <Paper padding={16}>
            <Box sx={{ display: 'flex', mb: 1.5 }}>
              <Text as="span" variant="title-sm">{t_i18n('Top entities by score')}</Text>
              <Box sx={{ flex: 1 }} />
              <Link to={`/dashboard/intelligence_requirements/${irId}/entities`}>{t_i18n('See all')}</Link>
            </Box>
            {inRequirement.slice(0, 8).map((m) => (
              <Box
                key={m.id}
                onClick={() => setSelected(m.id)}
                sx={{ display: 'grid', gridTemplateColumns: '28px 1fr 110px', alignItems: 'center', py: 0.75, px: 0.5, cursor: 'pointer', borderBottom: '1px solid', borderColor: 'divider', '&:hover': { bgcolor: 'action.hover' } }}
              >
                <ItemIcon type={m.match_entity_type} size="small" />
                <Box>
                  <Text as="div" variant="content-compact-medium">{m.entity?.representative.main ?? m.match_entity_id}</Text>
                  <Text as="div" variant="content-caption" style={{ opacity: 0.7 }}>{t_i18n(`entity_${m.match_entity_type}`)}</Text>
                </Box>
                <ScoreBar score={m.match_score} />
              </Box>
            ))}
          </Paper>
          <Paper padding={16}>
            <Text as="div" variant="title-sm" style={{ marginBottom: 12 }}>{t_i18n('Key intelligence questions')}</Text>
            {kiqs.length === 0 && <Text as="span" variant="content-caption">{t_i18n('No key intelligence question.')}</Text>}
            {kiqs.map((k) => (
              <Box key={k.id} sx={{ display: 'grid', gridTemplateColumns: '1fr auto', gap: 1, py: 0.75, borderBottom: '1px solid', borderColor: 'divider' }}>
                <Box>
                  <Text as="div" variant="content-compact">{k.text}</Text>
                  <Text as="div" variant="content-caption" style={{ opacity: 0.7 }}>{`→ ${k.criteria_ids.map((c) => criterionName(criteria, c)).join(', ') || t_i18n('no criterion')}`}</Text>
                </Box>
                <Chip label={t_i18n(k.answered ? 'Answered' : 'Unanswered')} severity={k.answered ? 'low' : 'high'} size="sm" />
              </Box>
            ))}
          </Paper>
        </Box>
      </Box>
      <IrMatchDrawer
        match={(matches.find((m) => m.id === selected) ?? null) as IrMatchData | null}
        criteria={criteria}
        onClose={() => setSelected(null)}
        onChanged={() => setFetchKey((k) => k + 1)}
      />
    </>
  );
};

export default IrOverview;
