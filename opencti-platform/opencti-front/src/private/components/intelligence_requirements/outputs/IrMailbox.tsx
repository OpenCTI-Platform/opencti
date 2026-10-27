import React, { useEffect, useMemo, useRef, useState } from 'react';
import { Link } from 'react-router';
import { Checkbox, Chip, Dialog, DialogContent, DialogDescription, DialogFooter, DialogTitle, Paper, Text } from '@filigran/design-system';
import Box from '@mui/material/Box';
import Button from '@common/button/Button';
import { useFormatter } from '../../../../components/i18n';
import ItemIcon from '../../../../components/ItemIcon';
import type { AgentOption } from '../../../../utils/ai/agentApi';
import { criterionName, type IrCriterionRef, KIND_CHIP, StatusChip } from './IrOutputCommon';
import { IrMatchDetails, type IrMatchData, useMatchDecision } from './IrMatchDrawer';
import { IrTriageCard, useIrTriage } from './IrTriage';
import type { IrInboxItemData } from './IrInbox';

// Mailbox view of the inbox: one line per entity (its open items grouped), a reading pane on the right,
// what is new since the last review, the decisions and the next item, from the keyboard too.

type Decision = 'accept' | 'reject' | 'acknowledge' | 'remove';

const KIND_DECISIONS: Record<string, Decision[]> = {
  proposed: ['accept', 'reject'],
  entered: ['acknowledge', 'remove'],
  score: ['acknowledge'],
  health: ['acknowledge'],
  brief: ['acknowledge'],
};

interface Thread {
  key: string;
  match: IrMatchData | null;
  items: IrInboxItemData[]; // newest first
  latest: string;
  name: string;
  entityType: string | null;
}

interface IrMailboxProps {
  irId: string;
  items: readonly IrInboxItemData[]; // open items of the current filter
  matches: readonly IrMatchData[];
  criteria: readonly IrCriterionRef[];
  sort: 'newest' | 'score';
  triageAgent: AgentOption | null;
  onDecideItems: (ids: string[], decision: Decision, onDone: () => void) => void;
  onRefresh: () => void;
  onReadBrief: (itemId: string) => void;
}

const lastReviewKey = (irId: string) => `ir-mailbox-last-review:${irId}`;

const isTyping = (target: EventTarget | null) => {
  const element = target as HTMLElement | null;
  if (!element) return false;
  return ['INPUT', 'TEXTAREA', 'SELECT'].includes(element.tagName) || element.isContentEditable || !!element.closest('[role="dialog"]');
};

const IrMailbox = ({ irId, items, matches, criteria, sort, triageAgent, onDecideItems, onRefresh, onReadBrief }: IrMailboxProps) => {
  const { t_i18n, nsdt } = useFormatter();
  // "New since your last review": the previous visit of this browser, recorded when leaving the mailbox
  const [since, setSince] = useState<string | null>(() => localStorage.getItem(lastReviewKey(irId)));
  useEffect(() => () => localStorage.setItem(lastReviewKey(irId), new Date().toISOString()), [irId]);
  const isNew = (date: string) => !since || date > since;

  // Items decided here leave the list at once, before the refetch confirms it
  const [decided, setDecided] = useState<Set<string>>(new Set());
  const hide = (ids: string[]) => setDecided((previous) => new Set([...previous, ...ids]));
  const threads = useMemo(() => {
    const byKey = new Map<string, Thread>();
    items.filter((item) => !decided.has(item.id)).forEach((item) => {
      const key = item.match?.id ?? `item:${item.id}`;
      const match = item.match ? (matches.find((m) => m.id === item.match?.id) ?? null) : null;
      const thread = byKey.get(key) ?? {
        key,
        match,
        items: [],
        latest: item.created_at,
        name: match?.entity?.representative.main ?? item.match?.entity?.representative.main ?? item.item_title,
        entityType: match?.match_entity_type ?? item.item_entity_type ?? null,
      };
      thread.items.push(item);
      if (item.created_at > thread.latest) thread.latest = item.created_at;
      byKey.set(key, thread);
    });
    const list = Array.from(byKey.values());
    list.forEach((t) => t.items.sort((a, b) => b.created_at.localeCompare(a.created_at)));
    const scoreOf = (t: Thread) => (!t.match || t.match.match_excluded ? -1 : t.match.match_score);
    return sort === 'score'
      ? list.sort((a, b) => scoreOf(b) - scoreOf(a) || b.latest.localeCompare(a.latest))
      : list.sort((a, b) => b.latest.localeCompare(a.latest));
  }, [items, matches, sort, decided]);

  const [selectedKey, setSelectedKey] = useState<string | null>(null);
  const [checked, setChecked] = useState<Set<string>>(new Set());
  const [confirm, setConfirm] = useState<Decision | null>(null);
  // Position of the selection, kept when the selected entity leaves the list after a decision: the next one takes its place
  const lastIndex = useRef(0);
  const found = threads.findIndex((t) => t.key === selectedKey);
  const index = found >= 0 ? found : Math.min(lastIndex.current, Math.max(0, threads.length - 1));
  lastIndex.current = index;
  const current = threads[index] ?? null;
  useEffect(() => {
    if (threads.length > 0 && found < 0) setSelectedKey(threads[index].key);
  }, [threads]);
  // A requirement without relevance rules does not rank its entities: no score to show
  const scored = threads.some((t) => (t.match?.match_score ?? 0) > 0);

  const goTo = (offset: number) => {
    if (threads.length === 0) return;
    setSelectedKey(threads[Math.max(0, Math.min(threads.length - 1, index + offset))].key);
  };
  // After a decision the thread leaves the list: the selection moves to the one that takes its place
  const afterDecision = () => onRefresh();
  const { decide: decideMatch, inFlight } = useMatchDecision(afterDecision);
  const triage = useIrTriage(irId, current?.match?.match_entity_id, triageAgent);

  const seenIds = (thread: Thread) => thread.items.filter((i) => (KIND_DECISIONS[i.item_kind] ?? []).includes('acknowledge')).map((i) => i.id);
  const inRequirement = (thread: Thread) => thread.match && ['auto', 'accepted'].includes(thread.match.match_status);
  const actions = (thread: Thread | null) => ({
    accept: !!thread?.match && thread.match.match_status === 'proposed',
    reject: !!thread?.match && thread.match.match_status === 'proposed',
    remove: !!thread && !!inRequirement(thread),
    seen: !!thread && seenIds(thread).length > 0,
  });
  const run = (decision: Decision, thread: Thread | null = current) => {
    if (!thread) return;
    const can = actions(thread);
    const applies = (decision === 'accept' && can.accept) || (decision === 'reject' && can.reject) || (decision === 'remove' && can.remove) || (decision === 'acknowledge' && can.seen);
    if (applies) hide(thread.items.map((i) => i.id));
    if (decision === 'accept' && can.accept && thread.match) decideMatch(thread.match.id, 'accepted');
    if (decision === 'reject' && can.reject && thread.match) decideMatch(thread.match.id, 'rejected');
    if (decision === 'remove' && can.remove && thread.match) decideMatch(thread.match.id, 'removed');
    if (decision === 'acknowledge' && can.seen) onDecideItems(seenIds(thread), 'acknowledge', afterDecision);
  };

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.metaKey || event.ctrlKey || event.altKey || isTyping(event.target)) return;
      const key = event.key.toLowerCase();
      if (key === 'arrowdown' || key === 'j' || key === 'n') goTo(1);
      else if (key === 'arrowup' || key === 'k') goTo(-1);
      else if (key === 'a') run('accept');
      else if (key === 'r') run('reject');
      else if (key === 's') run('acknowledge');
      else if (key === 'x') run('remove');
      else return;
      event.preventDefault();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  });

  // Mass decisions on the checked threads
  const selectedThreads = threads.filter((t) => checked.has(t.key));
  const bulkIds = (decision: Decision) => selectedThreads.flatMap((t) => t.items.filter((i) => (KIND_DECISIONS[i.item_kind] ?? []).includes(decision)).map((i) => i.id));
  const runBulk = (decision: Decision) => {
    setConfirm(null);
    const ids = bulkIds(decision);
    if (ids.length > 0) {
      hide(ids);
      onDecideItems(ids, decision, () => {
        setChecked(new Set());
        onRefresh();
      });
    }
  };
  const toggle = (key: string, value: boolean) => setChecked((previous) => {
    const next = new Set(previous);
    if (value) next.add(key);
    else next.delete(key);
    return next;
  });

  if (threads.length === 0) {
    return <Paper padding={24}><Text as="span" variant="content-base">{t_i18n('Nothing to review.')}</Text></Paper>;
  }
  const can = actions(current);
  const newCount = threads.filter((t) => isNew(t.latest)).length;
  return (
    <>
      <Box sx={{ display: 'flex', gap: 1, alignItems: 'center', flexWrap: 'wrap', mb: 1, px: 1.5, py: 1, border: '1px solid', borderColor: 'divider', borderRadius: 1 }}>
        <Checkbox
          checked={selectedThreads.length > 0 && selectedThreads.length === threads.length}
          onCheckedChange={(value) => setChecked(value === true ? new Set(threads.map((t) => t.key)) : new Set())}
          label={selectedThreads.length > 0 ? `${selectedThreads.length} ${t_i18n('selected')}` : `${t_i18n('Select all')} (${threads.length})`}
        />
        {selectedThreads.length > 0 && (
          <>
            <Button size="small" variant="secondary" disabled={bulkIds('acknowledge').length === 0} onClick={() => runBulk('acknowledge')}>{`${t_i18n('Mark as seen')} (${bulkIds('acknowledge').length})`}</Button>
            <Button size="small" disabled={bulkIds('accept').length === 0} onClick={() => runBulk('accept')}>{`${t_i18n('Accept')} (${bulkIds('accept').length})`}</Button>
            <Button size="small" variant="secondary" disabled={bulkIds('reject').length === 0} onClick={() => setConfirm('reject')}>{`${t_i18n('Reject')} (${bulkIds('reject').length})`}</Button>
            <Button size="small" variant="secondary" disabled={bulkIds('remove').length === 0} onClick={() => setConfirm('remove')}>{`${t_i18n('Remove')} (${bulkIds('remove').length})`}</Button>
          </>
        )}
        <Box sx={{ flex: 1 }} />
        <Text as="span" variant="content-caption" style={{ opacity: 0.7 }}>
          {since ? `${newCount} ${t_i18n('new since your last review')} (${nsdt(since)})` : t_i18n('First review in this browser')}
        </Text>
        <Button
          size="small"
          variant="tertiary"
          onClick={() => {
            const now = new Date().toISOString();
            localStorage.setItem(lastReviewKey(irId), now);
            setSince(now);
          }}
        >
          {t_i18n('Mark all as reviewed')}
        </Button>
      </Box>
      <Box sx={{ display: 'grid', gridTemplateColumns: 'minmax(0, 2fr) minmax(0, 3fr)', gap: 2, alignItems: 'start' }}>
        <Paper padding={0} style={{ maxHeight: 'calc(100vh - 300px)', overflowY: 'auto' }}>
          {threads.map((thread) => {
            const active = thread.key === current?.key;
            const kinds = Array.from(new Set(thread.items.map((i) => t_i18n(KIND_CHIP[i.item_kind]?.label ?? i.item_kind))));
            const criterionId = thread.items.find((i) => i.item_data.criterion_id)?.item_data.criterion_id;
            return (
              <Box
                key={thread.key}
                onClick={() => setSelectedKey(thread.key)}
                sx={{
                  display: 'grid',
                  gridTemplateColumns: '36px 1fr auto',
                  gap: 1,
                  px: 1.5,
                  py: 1.25,
                  cursor: 'pointer',
                  borderBottom: '1px solid',
                  borderColor: 'divider',
                  borderLeft: '3px solid',
                  borderLeftColor: active ? 'primary.main' : 'transparent',
                  bgcolor: active ? 'action.selected' : undefined,
                  '&:hover': { bgcolor: active ? 'action.selected' : 'action.hover' },
                }}
              >
                <Box onClick={(e) => e.stopPropagation()} sx={{ pt: 0.25 }}>
                  <Checkbox checked={checked.has(thread.key)} onCheckedChange={(value) => toggle(thread.key, value === true)} aria-label={t_i18n('Select')} />
                </Box>
                <Box sx={{ minWidth: 0, display: 'flex', flexDirection: 'column', gap: 0.5 }}>
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, minWidth: 0 }}>
                    {isNew(thread.latest) && <Box sx={{ width: 8, height: 8, borderRadius: '50%', bgcolor: 'primary.main', flexShrink: 0 }} aria-label={t_i18n('New')} />}
                    {thread.entityType && <ItemIcon type={thread.entityType} size="small" />}
                    <Text as="span" variant={isNew(thread.latest) ? 'content-compact-bold' : 'content-compact-medium'} style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{thread.name}</Text>
                  </Box>
                  <Box sx={{ display: 'flex', gap: 0.75, flexWrap: 'wrap', alignItems: 'center' }}>
                    {thread.entityType && <Chip label={t_i18n(`entity_${thread.entityType}`)} size="sm" />}
                    {thread.match && <StatusChip status={thread.match.match_status} excluded={thread.match.match_excluded} t={t_i18n} />}
                  </Box>
                  <Text as="div" variant="content-caption" style={{ opacity: 0.75, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {[
                      kinds.join(' · '),
                      thread.items.length > 1 ? `${thread.items.length} ${t_i18n('events')}` : null,
                      criterionId ? criterionName(criteria, criterionId) : null,
                    ].filter(Boolean).join(' · ')}
                  </Text>
                </Box>
                <Box sx={{ textAlign: 'right' }}>
                  {scored && <Text as="div" variant="title-sm">{thread.match && !thread.match.match_excluded ? String(thread.match.match_score) : '—'}</Text>}
                  <Text as="div" variant="content-caption" style={{ opacity: 0.6 }}>{nsdt(thread.latest)}</Text>
                </Box>
              </Box>
            );
          })}
        </Paper>
        {current && (
          <Paper padding={24} style={{ position: 'sticky', top: 16, maxHeight: 'calc(100vh - 300px)', overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 16 }}>
            <Box sx={{ display: 'flex', alignItems: 'flex-start', gap: 1.5 }}>
              <Box sx={{ flex: 1, minWidth: 0 }}>
                <Text as="div" variant="title-md">{current.name}</Text>
                <Box sx={{ display: 'flex', gap: 1, mt: 1, flexWrap: 'wrap' }}>
                  {current.entityType && <Chip label={t_i18n(`entity_${current.entityType}`)} />}
                  {current.match && <StatusChip status={current.match.match_status} excluded={current.match.match_excluded} t={t_i18n} />}
                </Box>
              </Box>
              {current.match && (
                <Box sx={{ textAlign: 'right' }}>
                  {scored && <Text as="div" variant="title-lg">{current.match.match_excluded ? '—' : String(current.match.match_score)}</Text>}
                  <Link to={`/dashboard/id/${current.match.match_entity_id}`} target="_blank" rel="noopener noreferrer">{t_i18n('Open entity')}</Link>
                </Box>
              )}
            </Box>
            <Box>
              <Text as="div" variant="content-compact-bold" style={{ marginBottom: 8 }}>{t_i18n('To review')}</Text>
              {current.items.map((item) => (
                <Box key={item.id} sx={{ display: 'grid', gridTemplateColumns: '1fr auto', gap: 1, py: 0.75, borderBottom: '1px solid', borderColor: 'divider' }}>
                  <Box sx={{ minWidth: 0 }}>
                    <Box sx={{ display: 'flex', gap: 1, alignItems: 'center' }}>
                      <Chip label={t_i18n(KIND_CHIP[item.item_kind]?.label ?? item.item_kind)} severity={KIND_CHIP[item.item_kind]?.severity} size="sm" />
                      {isNew(item.created_at) && <Chip label={t_i18n('New')} severity="info" size="sm" />}
                      <Text as="span" variant="content-compact">{item.item_title}</Text>
                    </Box>
                    {item.item_data.message && <Text as="div" variant="content-caption" style={{ opacity: 0.8 }}>{item.item_data.message}</Text>}
                    {item.item_kind === 'score' && (
                      <Text as="div" variant="content-caption" style={{ opacity: 0.8 }}>{`${item.item_data.from_score ?? 0} → ${item.item_data.to_score ?? 0} · ${(item.item_data.reasons ?? []).join(' · ')}`}</Text>
                    )}
                    {item.item_kind === 'brief' && <Button size="small" variant="tertiary" intent="ai" onClick={() => onReadBrief(item.id)}>{t_i18n('Read the brief')}</Button>}
                  </Box>
                  <Text as="span" variant="content-caption" style={{ opacity: 0.6 }}>{nsdt(item.created_at)}</Text>
                </Box>
              ))}
            </Box>
            {triage.available && (
              <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
                <Box>
                  <Button size="small" variant="secondary" intent="ai" disabled={triage.loading} onClick={triage.run}>
                    {triage.verdict ? t_i18n('Ask again') : t_i18n('Why is this of interest?')}
                  </Button>
                </Box>
                <IrTriageCard verdict={triage.verdict} loading={triage.loading} error={triage.error} />
              </Box>
            )}
            {current.match && <IrMatchDetails irId={irId} match={current.match} criteria={criteria} onDecided={afterDecision} embedded />}
            <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap', alignItems: 'center', pt: 1.5, borderTop: '1px solid', borderColor: 'divider', position: 'sticky', bottom: -24, bgcolor: 'background.paper', pb: 1 }}>
              {can.accept && <Button disabled={inFlight} onClick={() => run('accept')}>{`${t_i18n('Accept')} (A)`}</Button>}
              {can.reject && <Button variant="secondary" disabled={inFlight} onClick={() => run('reject')}>{`${t_i18n('Reject')} (R)`}</Button>}
              {can.seen && <Button variant="secondary" disabled={inFlight} onClick={() => run('acknowledge')}>{`${t_i18n('Mark as seen')} (S)`}</Button>}
              {can.remove && <Button variant="secondary" intent="destructive" disabled={inFlight} onClick={() => run('remove')}>{`${t_i18n('Remove from the requirement')} (X)`}</Button>}
              <Box sx={{ flex: 1 }} />
              <Text as="span" variant="content-caption" style={{ opacity: 0.6 }}>{`${index + 1} / ${threads.length}`}</Text>
              <Button variant="tertiary" disabled={index === 0} onClick={() => goTo(-1)}>{`↑ ${t_i18n('Previous')}`}</Button>
              <Button variant="tertiary" disabled={index >= threads.length - 1} onClick={() => goTo(1)}>{`${t_i18n('Next item')} ↓`}</Button>
            </Box>
          </Paper>
        )}
      </Box>
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
              {`${bulkIds(confirm).length} ${t_i18n('items')} · ${t_i18n('a rejected or removed entity does not come back into the requirement automatically.')}`}
            </DialogDescription>
            <DialogFooter>
              <Button variant="tertiary" onClick={() => setConfirm(null)}>{t_i18n('Cancel')}</Button>
              <Button intent="destructive" onClick={() => runBulk(confirm)}>{t_i18n(confirm === 'reject' ? 'Reject' : 'Remove')}</Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      )}
    </>
  );
};

export default IrMailbox;
