import React, { startTransition, useState } from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import { Checkbox, Chip, Dialog, DialogContent, DialogDescription, DialogFooter, DialogTitle, Paper, Text } from '@filigran/design-system';
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
import IrMailbox from './IrMailbox';
import { IrTriageCard, useIrTriage, useIrTriageAgent } from './IrTriage';
import Drawer from '@components/common/drawer/Drawer';
import XtmOneAISummaryDisplay from '@components/common/ai/XtmOneAISummaryDisplay';
import useIrAiGate from '../useIrAiGate';
import type { IrInboxBriefMutation } from './__generated__/IrInboxBriefMutation.graphql';
import type { AgentOption } from '../../../../utils/ai/agentApi';
import type { IrInboxQuery } from './__generated__/IrInboxQuery.graphql';
import type { IrInboxDecideMutation } from './__generated__/IrInboxDecideMutation.graphql';
import type { IrInboxBulkDecideMutation } from './__generated__/IrInboxBulkDecideMutation.graphql';

// ③ Inbox of the requirement: always the same kinds of items (proposed, entered, score threshold, health).

const inboxQuery = graphql`
  query IrInboxQuery($id: ID!) {
    intelligenceRequirement(id: $id) {
      id
      ir_inbox_open_count
      ir_subject_groups { id name }
      ir_scope_criteria { id name kind mode from_group_ids from_in_requirement }
      ir_inbox_counts { open proposed entered score health brief done }
    }
    intelligenceRequirementMatches(id: $id, first: 2000) {
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
          match_score_breakdown { name points hit reason kind criterion_id }
        }
      }
    }
    openItems: intelligenceRequirementItems(id: $id, statuses: [open], first: 500) {
      pageInfo { globalCount }
      edges {
        node {
          id
          item_kind
          item_status
          item_title
          item_result
          item_entity_type
          created_at
          item_data { criterion_id from_score to_score threshold reasons message content }
          match {
            id
            match_entity_id
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
          }
        }
      }
    }
    doneItems: intelligenceRequirementItems(id: $id, statuses: [done], first: 200) {
      pageInfo { globalCount }
      edges {
        node {
          id
          item_kind
          item_status
          item_title
          item_result
          item_entity_type
          created_at
          item_data { criterion_id from_score to_score threshold reasons message content }
          match {
            id
            match_entity_id
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

const bulkDecideMutation = graphql`
  mutation IrInboxBulkDecideMutation($ids: [ID!]!, $decision: IrItemDecision!) {
    intelligenceRequirementItemsDecide(ids: $ids, decision: $decision)
  }
`;

const briefMutation = graphql`
  mutation IrInboxBriefMutation($id: ID!) {
    intelligenceRequirementBriefGenerate(id: $id) {
      id
    }
  }
`;

// Decisions that apply to each kind of inbox item (same table as the backend)
const KIND_DECISIONS: Record<string, Decision[]> = {
  proposed: ['accept', 'reject'],
  entered: ['acknowledge', 'remove'],
  score: ['acknowledge'],
  health: ['acknowledge'],
  brief: ['acknowledge'],
};

type Filter = 'open' | 'proposed' | 'entered' | 'score' | 'health' | 'brief' | 'done';
type Sort = 'newest' | 'score';
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
    readonly message?: string | null;
    readonly content?: string | null;
  };
  readonly match?: {
    readonly id: string;
    readonly match_entity_id?: string;
    readonly match_score: number;
    readonly match_excluded: boolean;
    readonly entity?: { readonly representative: { readonly main: string } } | null;
    readonly match_explanations?: readonly IrExplanationData[];
  } | null;
}

const KIND_COLORS: Record<string, string> = { proposed: '#c084fc', entered: '#42caff', score: '#e6700f', health: '#e6c20f', brief: '#00f0bc' };

export const IrInboxItem = ({ item, criteria, groups = [], matches = [], onDecide, onDetails, compact, checked, onCheck, irId, triageAgent, onReadBrief }: {
  item: IrInboxItemData;
  criteria: readonly IrCriterionRef[];
  groups?: readonly IrGroupRef[];
  matches?: readonly IrChainMatch[];
  onDecide?: (id: string, decision: Decision) => void;
  onDetails?: (matchId: string) => void;
  compact?: boolean;
  checked?: boolean;
  onCheck?: (id: string, checked: boolean) => void;
  irId?: string;
  triageAgent?: AgentOption | null;
  onReadBrief?: (itemId: string) => void;
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
  const openDetails = item.match && onDetails ? () => onDetails(item.match!.id) : undefined;
  const triage = useIrTriage(irId ?? '', item.match?.match_entity_id, triageAgent ?? null);
  return (
    <Box
      onClick={compact ? openDetails : undefined}
      sx={{
        display: 'grid',
        gridTemplateColumns: onCheck ? '4px 40px 1fr auto' : '4px 1fr auto',
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
      {onCheck && (
        <Box sx={{ display: 'flex', justifyContent: 'center', pt: 1.75 }}>
          {!done && <Checkbox checked={!!checked} onCheckedChange={(value) => onCheck(item.id, value === true)} aria-label={t_i18n('Select')} />}
        </Box>
      )}
      <Box sx={{ px: 2, py: compact ? 1 : 1.5, display: 'flex', flexDirection: 'column', gap: compact ? 0.75 : 1 }}>
        <Box sx={{ display: 'flex', gap: 1, alignItems: 'center', flexWrap: 'wrap' }}>
          <Chip label={t_i18n(chip.label)} severity={chip.severity} />
          {item.item_entity_type && <Chip label={t_i18n(`entity_${item.item_entity_type}`)} />}
          {item.match && <Chip label={item.match.match_excluded ? t_i18n('Not eligible') : `${t_i18n('score')} ${item.match.match_score}`} />}
          {groupNames.map((name) => <Chip key={name} label={name} severity="info" />)}
          <Box sx={{ flex: 1 }} />
          <Text as="span" variant="content-caption" style={{ opacity: 0.7 }}>{nsdt(item.created_at)}</Text>
        </Box>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          {item.item_entity_type && <ItemIcon type={item.item_entity_type} size="small" />}
          <Text as="div" variant={compact ? 'content-compact-medium' : 'content-base-bold'}>{item.item_title}</Text>
        </Box>
        {!compact && item.item_data.message && (
          <Text as="div" variant="content-caption" style={{ opacity: 0.85 }}>{item.item_data.message}</Text>
        )}
        {!compact && item.item_kind === 'entered' && !item.item_data.criterion_id && (item.item_data.reasons ?? []).length > 0 && (
          <Text as="div" variant="content-caption" style={{ opacity: 0.85 }}>{`${t_i18n('Best scored')}: ${(item.item_data.reasons ?? []).join(' · ')}`}</Text>
        )}
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
        {!compact && <IrTriageCard verdict={triage.verdict} loading={triage.loading} error={triage.error} />}
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
          {item.item_kind === 'brief' && onReadBrief && (
            <Button size="small" fullWidth intent="ai" variant="secondary" onClick={() => onReadBrief(item.id)}>{t_i18n('Read the brief')}</Button>
          )}
          {!done && item.item_kind === 'brief' && (
            <Button size="small" fullWidth variant="tertiary" onClick={() => onDecide(item.id, 'acknowledge')}>{t_i18n('Mark as read')}</Button>
          )}
          {!done && (item.item_kind === 'score' || item.item_kind === 'health') && (
            <Button size="small" fullWidth variant="secondary" onClick={() => onDecide(item.id, 'acknowledge')}>{t_i18n('Mark as seen')}</Button>
          )}
          {!done && triage.available && (
            <Button size="small" fullWidth variant="tertiary" intent="ai" disabled={triage.loading} onClick={triage.run}>
              {triage.verdict ? t_i18n('Ask again') : t_i18n('Why is this of interest?')}
            </Button>
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
  const [sort, setSort] = useState<Sort>('newest');
  const [checked, setChecked] = useState<Set<string>>(new Set());
  const [confirm, setConfirm] = useState<Decision | null>(null);
  // Mailbox (one line per entity, reading pane) or list of items; remembered in this browser
  const [view, setView] = useState<'mailbox' | 'list'>(() => (localStorage.getItem('ir-inbox-view') === 'list' ? 'list' : 'mailbox'));
  const changeView = (value: 'mailbox' | 'list') => {
    localStorage.setItem('ir-inbox-view', value);
    setView(value);
  };
  const data = useLazyLoadQuery<IrInboxQuery>(inboxQuery, { id: irId }, { fetchPolicy: 'network-only', fetchKey });
  const [commit] = useApiMutation<IrInboxDecideMutation>(decideMutation);
  const [commitBulk, bulkInFlight] = useApiMutation<IrInboxBulkDecideMutation>(bulkDecideMutation);
  const triageAgent = useIrTriageAgent();
  const briefGate = useIrAiGate('AI brief');
  const canBrief = briefGate.visible && briefGate.xtmOneConfigured && !briefGate.termsPending && !briefGate.disabledReason;
  const [commitBrief, briefInFlight] = useApiMutation<IrInboxBriefMutation>(briefMutation);
  const [briefId, setBriefId] = useState<string | null>(null);
  const criteria = data.intelligenceRequirement?.ir_scope_criteria ?? [];
  const groups = data.intelligenceRequirement?.ir_subject_groups ?? [];
  const matches = (data.intelligenceRequirementMatches?.edges ?? []).map((e) => e.node);
  // Open items and the latest done items are queried separately: the open ones must never be hidden by done ones
  const open = (data.openItems?.edges ?? []).map((e) => e.node);
  const items = [...open, ...(data.doneItems?.edges ?? []).map((e) => e.node)];
  const counts = data.intelligenceRequirement?.ir_inbox_counts;
  const openTotal = counts?.open ?? open.length;
  const visible = items.filter((i) => {
    if (filter === 'done') return i.item_status !== 'open';
    if (filter === 'open') return i.item_status === 'open';
    return i.item_status === 'open' && i.item_kind === filter;
  });
  // Highest score first (excluded entities and items without entity last), newest first on ties
  const scoreOf = (i: typeof items[number]) => (!i.match || i.match.match_excluded ? -1 : i.match.match_score);
  const sorted = sort === 'score'
    ? [...visible].sort((a, b) => scoreOf(b) - scoreOf(a) || b.created_at.localeCompare(a.created_at))
    : visible;
  // Refetch in a transition: the current view stays on screen instead of being replaced by a loader
  const refresh = () => startTransition(() => setFetchKey((k) => k + 1));
  const decide = (id: string, decision: Decision) => {
    commit({ variables: { id, decision }, onCompleted: refresh });
  };
  // Mass operations on the selected open items of the current view
  const selectable = sorted.filter((i) => i.item_status === 'open');
  const selectedItems = selectable.filter((i) => checked.has(i.id));
  const allSelected = selectable.length > 0 && selectedItems.length === selectable.length;
  const toggle = (id: string, value: boolean) => setChecked((previous) => {
    const next = new Set(previous);
    if (value) next.add(id);
    else next.delete(id);
    return next;
  });
  const applicable = (decision: Decision) => selectedItems.filter((i) => (KIND_DECISIONS[i.item_kind] ?? []).includes(decision));
  const runBulk = (decision: Decision) => {
    const ids = applicable(decision).map((i) => i.id);
    setConfirm(null);
    if (ids.length === 0) return;
    const onCompleted = () => {
      setChecked(new Set());
      refresh();
    };
    commitBulk({ variables: { ids, decision }, onCompleted });
  };
  const bulkButton = (decision: Decision, label: string, variant: 'primary' | 'secondary', needsConfirm = false) => {
    const count = applicable(decision).length;
    return (
      <Button size="small" variant={variant} disabled={count === 0 || bulkInFlight} onClick={() => (needsConfirm ? setConfirm(decision) : runBulk(decision))}>
        {`${t_i18n(label)} (${count})`}
      </Button>
    );
  };
  const generateBrief = () => {
    const onCompleted = (response: IrInboxBriefMutation['response']) => {
      refresh();
      setFilter('brief');
      setBriefId(response.intelligenceRequirementBriefGenerate?.id ?? null);
    };
    commitBrief({ variables: { id: irId }, onCompleted });
  };
  const changeFilter = (value: Filter) => {
    setFilter(value);
    setChecked(new Set());
  };
  const filterButton = (value: Filter, label: string, count: number) => (
    <Button key={value} size="small" variant={filter === value ? 'primary' : 'secondary'} onClick={() => changeFilter(value)}>{`${t_i18n(label)} (${count})`}</Button>
  );
  return (
    <>
      <Box sx={{ display: 'flex', gap: 1, mb: 2, flexWrap: 'wrap' }}>
        {filterButton('open', 'To review', openTotal)}
        {filterButton('proposed', 'Proposed', counts?.proposed ?? 0)}
        {filterButton('entered', 'Entered', counts?.entered ?? 0)}
        {filterButton('score', 'Score threshold', counts?.score ?? 0)}
        {filterButton('health', 'Health', counts?.health ?? 0)}
        {filterButton('brief', 'Briefs', counts?.brief ?? 0)}
        {filterButton('done', 'Done', counts?.done ?? 0)}
        <Box sx={{ flex: 1 }} />
        {canBrief && (
          <Button size="small" intent="ai" variant="secondary" disabled={briefInFlight} onClick={generateBrief}>
            {briefInFlight ? t_i18n('Generating the brief… (about 30 s)') : t_i18n('Generate a brief now')}
          </Button>
        )}
        <Text as="span" variant="content-caption" style={{ alignSelf: 'center', opacity: 0.7 }}>{t_i18n('View')}</Text>
        <Button size="small" variant={view === 'mailbox' ? 'primary' : 'tertiary'} onClick={() => changeView('mailbox')}>{t_i18n('Mailbox')}</Button>
        <Button size="small" variant={view === 'list' ? 'primary' : 'tertiary'} onClick={() => changeView('list')}>{t_i18n('List')}</Button>
        <Text as="span" variant="content-caption" style={{ alignSelf: 'center', opacity: 0.7 }}>{t_i18n('Sort by')}</Text>
        <Button size="small" variant={sort === 'newest' ? 'primary' : 'tertiary'} onClick={() => setSort('newest')}>{t_i18n('Newest first')}</Button>
        <Button size="small" variant={sort === 'score' ? 'primary' : 'tertiary'} onClick={() => setSort('score')}>{t_i18n('Highest score first')}</Button>
      </Box>
      {filter !== 'done' && openTotal > open.length && (
        <Text as="div" variant="content-caption" style={{ opacity: 0.7, marginBottom: 8 }}>
          {`${t_i18n('Showing the')} ${open.length} ${t_i18n('most recent open items out of')} ${openTotal}`}
        </Text>
      )}
      {filter === 'done' && (data.doneItems?.pageInfo.globalCount ?? 0) > (data.doneItems?.edges.length ?? 0) && (
        <Text as="div" variant="content-caption" style={{ opacity: 0.7, marginBottom: 8 }}>
          {`${t_i18n('Showing the')} ${data.doneItems?.edges.length ?? 0} ${t_i18n('most recent done items out of')} ${data.doneItems?.pageInfo.globalCount ?? 0}`}
        </Text>
      )}
      {view === 'mailbox' && filter !== 'done' && (
        <IrMailbox
          irId={irId}
          items={sorted.filter((i) => i.item_status === 'open') as unknown as IrInboxItemData[]}
          matches={matches as unknown as IrMatchData[]}
          criteria={criteria}
          sort={sort}
          triageAgent={triageAgent}
          onDecideItems={(ids, decision, onDone) => commitBulk({ variables: { ids, decision }, onCompleted: onDone })}
          onRefresh={refresh}
          onReadBrief={setBriefId}
        />
      )}
      {(view === 'list' || filter === 'done') && selectable.length > 0 && (
        <Box sx={{ display: 'flex', gap: 1, alignItems: 'center', flexWrap: 'wrap', mb: 1, px: 1.5, py: 1, border: '1px solid', borderColor: 'divider', borderRadius: 1 }}>
          <Checkbox
            checked={allSelected}
            onCheckedChange={(value) => setChecked(value === true ? new Set(selectable.map((i) => i.id)) : new Set())}
            label={selectedItems.length > 0 ? `${selectedItems.length} ${t_i18n('selected')}` : `${t_i18n('Select all')} (${selectable.length})`}
          />
          <Box sx={{ flex: 1 }} />
          {selectedItems.length > 0 && (
            <>
              {bulkButton('acknowledge', 'Mark as seen', 'secondary')}
              {bulkButton('accept', 'Accept into the requirement', 'primary')}
              {bulkButton('reject', 'Reject', 'secondary', true)}
              {bulkButton('remove', 'Remove from the requirement', 'secondary', true)}
              <Button size="small" variant="tertiary" onClick={() => setChecked(new Set())}>{t_i18n('Clear selection')}</Button>
            </>
          )}
        </Box>
      )}
      {(view === 'list' || filter === 'done') && (visible.length === 0
        ? <Paper padding={24}><Text as="span" variant="content-base">{t_i18n('Nothing to review.')}</Text></Paper>
        : sorted.map((item) => (
            <IrInboxItem
              key={item.id}
              item={item}
              criteria={criteria}
              groups={groups}
              matches={matches}
              onDecide={decide}
              onDetails={setSelected}
              checked={checked.has(item.id)}
              onCheck={toggle}
              irId={irId}
              triageAgent={triageAgent}
              onReadBrief={setBriefId}
            />
          )))}
      {confirm && (
        <Dialog
          open
          onOpenChange={(isOpen) => {
            if (!isOpen) setConfirm(null);
          }}
        >
          <DialogContent>
            <DialogTitle>{t_i18n(confirm === 'reject' ? 'Reject the selected proposals?' : 'Remove the selected entities from the requirement?')}</DialogTitle>
            <DialogDescription>
              {`${applicable(confirm).length} ${t_i18n('items')} · ${t_i18n('a rejected or removed entity does not come back into the requirement automatically.')}`}
            </DialogDescription>
            <DialogFooter>
              <Button variant="tertiary" onClick={() => setConfirm(null)}>{t_i18n('Cancel')}</Button>
              <Button intent="destructive" onClick={() => runBulk(confirm)}>{t_i18n(confirm === 'reject' ? 'Reject' : 'Remove')}</Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      )}
      <Drawer open={!!briefId} onClose={() => setBriefId(null)} title={items.find((i) => i.id === briefId)?.item_title ?? t_i18n('AI brief')} size="large">
        <XtmOneAISummaryDisplay
          disclaimerText={t_i18n('This brief was written by an XTM One agent from the content of the requirement. It has been generated by AI and can contain mistakes.')}
          noAgent={false}
          loading={false}
          content={items.find((i) => i.id === briefId)?.item_data.content ?? ''}
          generatedAt={items.find((i) => i.id === briefId)?.created_at ?? null}
          onRetry={generateBrief}
        />
      </Drawer>
      <IrMatchDrawer
        irId={irId}
        match={(matches.find((m) => m.id === selected) ?? null) as IrMatchData | null}
        criteria={criteria}
        onClose={() => setSelected(null)}
        onChanged={refresh}
      />
    </>
  );
};

export default IrInbox;
