import React, { useState } from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import { Chip, Paper, Text } from '@filigran/design-system';
import Box from '@mui/material/Box';
import Button from '@common/button/Button';
import { useFormatter } from '../../../../components/i18n';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { criterionName, KIND_CHIP, ScoreBar } from './IrOutputCommon';
import type { IrInboxQuery } from './__generated__/IrInboxQuery.graphql';
import type { IrInboxDecideMutation } from './__generated__/IrInboxDecideMutation.graphql';

// ③ Inbox of the requirement: always the same kinds of items (proposed, entered, score threshold, health).

const inboxQuery = graphql`
  query IrInboxQuery($id: ID!) {
    intelligenceRequirement(id: $id) {
      id
      ir_scope_criteria { id name kind }
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
          match { id match_status match_score match_excluded }
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
  readonly match?: { readonly match_score: number; readonly match_excluded: boolean } | null;
}

export const IrInboxItem = ({ item, criteria, onDecide, compact }: {
  item: IrInboxItemData;
  criteria: readonly { id: string; name: string; kind: string }[];
  onDecide?: (id: string, decision: 'accept' | 'reject' | 'acknowledge' | 'remove') => void;
  compact?: boolean;
}) => {
  const { t_i18n, nsdt } = useFormatter();
  const chip = KIND_CHIP[item.item_kind] ?? KIND_CHIP.entered;
  const done = item.item_status !== 'open';
  const colors: Record<string, string> = { proposed: '#c084fc', entered: '#42caff', score: '#e6700f', health: '#e6c20f' };
  return (
    <Box sx={{ display: 'grid', gridTemplateColumns: '4px 1fr auto', border: '1px solid', borderColor: 'divider', borderRadius: 1, mb: 1, overflow: 'hidden', opacity: done ? 0.55 : 1 }}>
      <Box sx={{ bgcolor: colors[item.item_kind] ?? '#42caff' }} />
      <Box sx={{ px: 2, py: compact ? 1 : 1.5 }}>
        <Box sx={{ display: 'flex', gap: 1, alignItems: 'center', flexWrap: 'wrap' }}>
          <Chip label={t_i18n(chip.label)} severity={chip.severity} size="sm" />
          {item.item_entity_type && <Chip label={t_i18n(`entity_${item.item_entity_type}`)} size="sm" />}
          {item.match && <ScoreBar score={item.match.match_score} excluded={item.match.match_excluded} />}
          <Text as="span" variant="content-caption" style={{ opacity: 0.7 }}>{nsdt(item.created_at)}</Text>
        </Box>
        <Text as="div" variant={compact ? 'content-compact-medium' : 'content-base-bold'} style={{ marginTop: 6 }}>{item.item_title}</Text>
        {!compact && item.item_kind === 'score' && (
          <Text as="div" variant="content-caption" style={{ marginTop: 4 }}>
            {`${item.item_data.from_score ?? 0} → ${item.item_data.to_score ?? 0} · ${(item.item_data.reasons ?? []).join(' · ')}`}
          </Text>
        )}
        {!compact && (item.item_kind === 'proposed' || item.item_kind === 'entered') && item.item_data.criterion_id && (
          <Text as="div" variant="content-caption" style={{ marginTop: 4, opacity: 0.8 }}>{`${t_i18n('Criterion')}: ${criterionName(criteria, item.item_data.criterion_id)}`}</Text>
        )}
      </Box>
      {onDecide && (
        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 0.75, p: 1.5, minWidth: 180, justifyContent: 'center' }}>
          {done && <Text as="span" variant="content-caption">{item.item_result ?? t_i18n('Done')}</Text>}
          {!done && item.item_kind === 'proposed' && (
            <>
              <Button size="small" onClick={() => onDecide(item.id, 'accept')}>{t_i18n('Accept into the requirement')}</Button>
              <Button size="small" variant="secondary" onClick={() => onDecide(item.id, 'reject')}>{t_i18n('Reject')}</Button>
            </>
          )}
          {!done && item.item_kind === 'entered' && (
            <>
              <Button size="small" variant="secondary" onClick={() => onDecide(item.id, 'acknowledge')}>{t_i18n('Mark as seen')}</Button>
              <Button size="small" variant="tertiary" onClick={() => onDecide(item.id, 'remove')}>{t_i18n('Remove from the requirement')}</Button>
            </>
          )}
          {!done && (item.item_kind === 'score' || item.item_kind === 'health') && (
            <Button size="small" variant="secondary" onClick={() => onDecide(item.id, 'acknowledge')}>{t_i18n('Mark as seen')}</Button>
          )}
        </Box>
      )}
    </Box>
  );
};

const IrInbox = ({ irId }: { irId: string }) => {
  const { t_i18n } = useFormatter();
  const [fetchKey, setFetchKey] = useState(0);
  const [filter, setFilter] = useState<Filter>('open');
  const data = useLazyLoadQuery<IrInboxQuery>(inboxQuery, { id: irId }, { fetchPolicy: 'network-only', fetchKey });
  const [commit] = useApiMutation<IrInboxDecideMutation>(decideMutation);
  const criteria = data.intelligenceRequirement?.ir_scope_criteria ?? [];
  const items = (data.intelligenceRequirementItems?.edges ?? []).map((e) => e.node);
  const open = items.filter((i) => i.item_status === 'open');
  const visible = items.filter((i) => {
    if (filter === 'done') return i.item_status !== 'open';
    if (filter === 'open') return i.item_status === 'open';
    return i.item_status === 'open' && i.item_kind === filter;
  });
  const decide = (id: string, decision: 'accept' | 'reject' | 'acknowledge' | 'remove') => {
    commit({ variables: { id, decision }, onCompleted: () => setFetchKey((k) => k + 1) });
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
        : visible.map((item) => <IrInboxItem key={item.id} item={item} criteria={criteria} onDecide={decide} />)}
    </>
  );
};

export default IrInbox;
