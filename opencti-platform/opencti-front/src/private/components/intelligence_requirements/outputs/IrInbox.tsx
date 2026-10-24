import React, { useState } from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import { Chip, Paper, Text } from '@filigran/design-system';
import Box from '@mui/material/Box';
import Button from '@common/button/Button';
import { useFormatter } from '../../../../components/i18n';
import ItemIcon from '../../../../components/ItemIcon';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import {
  buildProofChain,
  criterionName,
  explanationSentence,
  type IrChainMatch,
  type IrCriterionRef,
  type IrExplanationData,
  type IrGroupRef,
  KIND_CHIP,
  ProofChain,
} from './IrOutputCommon';
import IrMatchDrawer, { type IrMatchData } from './IrMatchDrawer';
import type { IrInboxQuery } from './__generated__/IrInboxQuery.graphql';
import type { IrInboxDecideMutation } from './__generated__/IrInboxDecideMutation.graphql';

// ③ Inbox of the requirement: always the same kinds of items (proposed, entered, score threshold, health).

const inboxQuery = graphql`
  query IrInboxQuery($id: ID!) {
    intelligenceRequirement(id: $id) {
      id
      ir_subject_groups { id name }
      ir_scope_criteria { id name kind mode from_group_ids from_in_requirement }
    }
    intelligenceRequirementMatches(id: $id, first: 500) {
      edges {
        node {
          id
          match_status
          match_score
          match_excluded
          match_entity_type
          match_entity_id
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
    intelligenceRequirementItems(id: $id, first: 200) {
      edges {
        node {
          id
          item_kind
          item_status
          item_title
          item_result
          item_entity_type
          created_at
          item_data { criterion_id from_score to_score threshold reasons message }
          match {
            id
            match_status
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
              relationship {
                confidence
                created
                start_time
                createdBy { name }
              }
            }
            match_other_requirements { id name }
          }
        }
      }
    }
  }
`;

const decideMutation = graphql`
  mutation IrInboxDecideMutation($id: ID!, $decision: IrItemDecision!) {
    intelligenceRequirementItemDecide(id: $id, decision: $decision) {
      id
      item_status
      item_result
    }
  }
`;

type Filter = 'open' | 'proposed' | 'entered' | 'score' | 'done';
type Decision = 'accept' | 'reject' | 'acknowledge' | 'remove';

export interface IrInboxItemData {
  readonly id: string;
  readonly item_kind: string;
  readonly item_status: string;
  readonly item_title: string;
  readonly item_result?: string | null;
  readonly item_entity_type?: string | null;
  readonly created_at: string;
  readonly item_data: {
    readonly criterion_id?: string | null;
    readonly from_score?: number | null;
    readonly to_score?: number | null;
    readonly reasons?: readonly string[] | null;
  };
  readonly match?: {
    readonly id: string;
    readonly match_score: number;
    readonly match_excluded: boolean;
    readonly entity?: { readonly representative: { readonly main: string } } | null;
    readonly match_explanations?: readonly IrExplanationData[];
    readonly match_other_requirements?: readonly { readonly id: string; readonly name: string }[];
  } | null;
}

const KIND_COLORS: Record<string, string> = { proposed: '#c084fc', entered: '#42caff', score: '#e6700f', health: '#e6c20f' };

export const IrInboxItem = ({ item, criteria, groups = [], matches = [], onDecide, onDetails, compact }: {
  item: IrInboxItemData;
  criteria: readonly IrCriterionRef[];
  groups?: readonly IrGroupRef[];
  matches?: readonly IrChainMatch[];
  onDecide?: (id: string, decision: Decision) => void;
  onDetails?: (matchId: string) => void;
  compact?: boolean;
}) => {
  const { t_i18n, nsdt, fsd } = useFormatter();
  const chip = KIND_CHIP[item.item_kind] ?? KIND_CHIP.entered;
  const done = item.item_status !== 'open';
  const entering = item.item_kind === 'proposed' || item.item_kind === 'entered';
  const entityName = item.match?.entity?.representative.main ?? '';
  const criterion = criteria.find((c) => c.id === item.item_data.criterion_id);
  const proofs = entering
    ? (item.match?.match_explanations ?? []).filter((e) => !item.item_data.criterion_id || e.criterion_id === item.item_data.criterion_id)
    : [];
  const graphProof = proofs.find((e) => e.kind === 'graph');
  const chain = graphProof ? buildProofChain(graphProof, entityName, criteria, matches) : null;
  const groupNames = (chain?.groupIds ?? criterion?.from_group_ids ?? []).map((id) => groups.find((g) => g.id === id)?.name).filter((n): n is string => !!n);
  const relationship = chain?.first.relationship;
  // start_time defaults to 1970 when the source did not give one: fall back on the creation date.
  const startTime = relationship?.start_time && new Date(relationship.start_time).getFullYear() > 1970 ? relationship.start_time : null;
  const factDate = startTime ?? relationship?.created;
  const others = item.match?.match_other_requirements ?? [];
  const openDetails = item.match && onDetails ? () => onDetails(item.match!.id) : undefined;
  return (
    <Box
      onClick={compact ? openDetails : undefined}
      sx={{
        display: 'grid',
        gridTemplateColumns: '4px 1fr auto',
        border: '1px solid',
        borderColor: 'divider',
        borderRadius: 1,
        mb: 1,
        overflow: 'hidden',
        opacity: done ? 0.55 : 1,
        cursor: compact && openDetails ? 'pointer' : undefined,
        '&:hover': compact && openDetails ? { bgcolor: 'action.hover' } : undefined,
      }}
    >
      <Box sx={{ bgcolor: KIND_COLORS[item.item_kind] ?? '#42caff' }} />
      <Box sx={{ px: 2, py: compact ? 1 : 1.5, display: 'flex', flexDirection: 'column', gap: compact ? 0.75 : 1 }}>
        <Box sx={{ display: 'flex', gap: 1, alignItems: 'center', flexWrap: 'wrap' }}>
          <Chip label={t_i18n(chip.label)} severity={chip.severity} />
          {item.item_entity_type && <Chip label={t_i18n(`entity_${item.item_entity_type}`)} />}
          {item.match && <Chip label={item.match.match_excluded ? t_i18n('Excluded') : `${t_i18n('score')} ${item.match.match_score}`} />}
          {groupNames.map((name) => <Chip key={name} label={name} severity="info" />)}
          <Box sx={{ flex: 1 }} />
          <Text as="span" variant="content-caption" style={{ opacity: 0.7 }}>{nsdt(item.created_at)}</Text>
        </Box>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          {item.item_entity_type && <ItemIcon type={item.item_entity_type} size="small" />}
          <Text as="div" variant={compact ? 'content-compact-medium' : 'content-base-bold'}>{item.item_title}</Text>
        </Box>
        {!compact && item.item_kind === 'score' && (
          <Text as="div" variant="content-caption">
            {`${item.item_data.from_score ?? 0} → ${item.item_data.to_score ?? 0} · ${(item.item_data.reasons ?? []).join(' · ')}`}
          </Text>
        )}
        {!compact && entering && criterion && (
          <Text as="div" variant="content-caption" style={{ opacity: 0.8 }}>
            {`${t_i18n('Criterion')} “${criterion.name}”${criterion.mode ? ` (${t_i18n('mode')} ${t_i18n(criterion.mode === 'propose' ? 'Propose' : 'Auto')})` : ''}`}
          </Text>
        )}
        {!compact && entering && !criterion && item.item_data.criterion_id && (
          <Text as="div" variant="content-caption" style={{ opacity: 0.8 }}>{`${t_i18n('Criterion')}: ${criterionName(criteria, item.item_data.criterion_id)}`}</Text>
        )}
        {chain && (
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, flexWrap: 'wrap' }}>
            <ProofChain chain={chain} />
            {proofs.length > 1 && <Text as="span" variant="content-caption" style={{ opacity: 0.7 }}>{`+${proofs.length - 1} ${t_i18n('other proofs')}`}</Text>}
          </Box>
        )}
        {!chain && proofs.length > 0 && (
          <Text as="div" variant="content-caption" style={{ opacity: 0.8 }}>{proofs.slice(0, 3).map((e) => explanationSentence(e, entityName)).join(' · ')}</Text>
        )}
        {!compact && relationship && (
          <Box sx={{ display: 'flex', gap: 2, opacity: 0.7 }}>
            {relationship.createdBy && <Text as="span" variant="content-caption">{`▸ ${relationship.createdBy.name}`}</Text>}
            {relationship.confidence != null && <Text as="span" variant="content-caption">{`▸ ${t_i18n('confidence')} ${relationship.confidence}`}</Text>}
            {factDate && <Text as="span" variant="content-caption">{`▸ ${fsd(factDate)}`}</Text>}
          </Box>
        )}
        {!compact && others.length > 0 && (
          <Box sx={{ display: 'flex', gap: 1, alignItems: 'center', flexWrap: 'wrap' }}>
            <Text as="span" variant="content-caption" style={{ opacity: 0.7 }}>{t_i18n('Also in')}</Text>
            {others.map((o) => <Chip key={o.id} label={o.name} />)}
            <Text as="span" variant="content-caption" style={{ opacity: 0.7 }}>{`(${t_i18n('triaged separately')})`}</Text>
          </Box>
        )}
      </Box>
      {onDecide && (
        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 0.75, p: 1.5, minWidth: 190, justifyContent: 'center' }}>
          {done && <Text as="span" variant="content-caption">{item.item_result ?? t_i18n('Done')}</Text>}
          {!done && item.item_kind === 'proposed' && (
            <>
              <Button size="small" fullWidth onClick={() => onDecide(item.id, 'accept')}>{`✓ ${t_i18n('Accept into the requirement')}`}</Button>
              <Button size="small" fullWidth variant="secondary" onClick={() => onDecide(item.id, 'reject')}>{`✕ ${t_i18n('Reject')}`}</Button>
            </>
          )}
          {!done && item.item_kind === 'entered' && (
            <>
              <Button size="small" fullWidth variant="secondary" onClick={() => onDecide(item.id, 'acknowledge')}>{t_i18n('Mark as seen')}</Button>
              <Button size="small" fullWidth variant="secondary" onClick={() => onDecide(item.id, 'remove')}>{t_i18n('Remove from the requirement')}</Button>
            </>
          )}
          {!done && (item.item_kind === 'score' || item.item_kind === 'health') && (
            <Button size="small" fullWidth variant="secondary" onClick={() => onDecide(item.id, 'acknowledge')}>{t_i18n('Mark as seen')}</Button>
          )}
          {openDetails && <Button size="small" fullWidth variant="tertiary" onClick={openDetails}>{t_i18n('Details')}</Button>}
        </Box>
      )}
    </Box>
  );
};

const IrInbox = ({ irId }: { irId: string }) => {
  const { t_i18n } = useFormatter();
  const [fetchKey, setFetchKey] = useState(0);
  const [filter, setFilter] = useState<Filter>('open');
  const [selected, setSelected] = useState<string | null>(null);
  const data = useLazyLoadQuery<IrInboxQuery>(inboxQuery, { id: irId }, { fetchPolicy: 'network-only', fetchKey });
  const [commit] = useApiMutation<IrInboxDecideMutation>(decideMutation);
  const criteria = data.intelligenceRequirement?.ir_scope_criteria ?? [];
  const groups = data.intelligenceRequirement?.ir_subject_groups ?? [];
  const matches = (data.intelligenceRequirementMatches?.edges ?? []).map((e) => e.node);
  const items = (data.intelligenceRequirementItems?.edges ?? []).map((e) => e.node);
  const open = items.filter((i) => i.item_status === 'open');
  const visible = items.filter((i) => {
    if (filter === 'done') return i.item_status !== 'open';
    if (filter === 'open') return i.item_status === 'open';
    return i.item_status === 'open' && i.item_kind === filter;
  });
  const refresh = () => setFetchKey((k) => k + 1);
  const decide = (id: string, decision: Decision) => {
    commit({ variables: { id, decision }, onCompleted: refresh });
  };
  const filterButton = (value: Filter, label: string, count: number) => (
    <Button key={value} size="small" variant={filter === value ? 'primary' : 'secondary'} onClick={() => setFilter(value)}>{`${t_i18n(label)} (${count})`}</Button>
  );
  return (
    <>
      <Box sx={{ display: 'flex', gap: 1, mb: 2, flexWrap: 'wrap' }}>
        {filterButton('open', 'To review', open.length)}
        {filterButton('proposed', 'Proposed', open.filter((i) => i.item_kind === 'proposed').length)}
        {filterButton('entered', 'Entered', open.filter((i) => i.item_kind === 'entered').length)}
        {filterButton('score', 'Score threshold', open.filter((i) => i.item_kind === 'score').length)}
        {filterButton('done', 'Done', items.length - open.length)}
      </Box>
      {visible.length === 0
        ? <Paper padding={24}><Text as="span" variant="content-base">{t_i18n('Nothing to review.')}</Text></Paper>
        : visible.map((item) => (
            <IrInboxItem key={item.id} item={item} criteria={criteria} groups={groups} matches={matches} onDecide={decide} onDetails={setSelected} />
          ))}
      <IrMatchDrawer
        match={(matches.find((m) => m.id === selected) ?? null) as IrMatchData | null}
        criteria={criteria}
        onClose={() => setSelected(null)}
        onChanged={refresh}
      />
    </>
  );
};

export default IrInbox;
