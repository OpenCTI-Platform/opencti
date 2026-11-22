import React, { useEffect, useMemo, useRef, useState } from 'react';
import { fetchQuery, graphql } from 'react-relay';
import { Chip, Paper, Text } from '@filigran/design-system';
import Box from '@mui/material/Box';
import { useFormatter } from '../../../../components/i18n';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { environment } from '../../../../relay/environment';
import { draftToInput, type IrCriterionDraft, type IrDraft, type IrEntityOption } from './irConfigTypes';
import { IrEntityPicker } from './IrFields';
import { irGroupLabel } from './irConstants';
import { ConditionStatus } from '../outputs/IrOutputCommon';
import type { IrDryRunPanelPreviewQuery, IrDryRunPanelPreviewQuery$data } from './__generated__/IrDryRunPanelPreviewQuery.graphql';
import type { IrDryRunPanelTestQuery, IrDryRunPanelTestQuery$data } from './__generated__/IrDryRunPanelTestQuery.graphql';

// Dry run of the configuration being written, next to the form: what each subject and criterion represents today,
// and the verdict of the configuration on an entity chosen by the analyst. Nothing is saved or written.
// The preview ids are aliased out of `id`: a preview group, criterion or entity shares its id with the saved subject
// group or the entity, and Relay would merge the records and drop the fields the requirement header reads.

const previewQuery = graphql`
  query IrDryRunPanelPreviewQuery($input: IntelligenceRequirementInput!) {
    intelligenceRequirementPreview(input: $input) {
      valid
      errors
      warnings
      groups { group_id: id name kind matching_count unresolved_ids entities { entity_id: id } }
      criteria { criterion_id: id name kind today_count note warnings }
    }
  }
`;

const testQuery = graphql`
  query IrDryRunPanelTestQuery($input: IntelligenceRequirementInput!, $entityId: ID!, $irId: ID) {
    intelligenceRequirementTestEntity(input: $input, entity_id: $entityId, ir_id: $irId) {
      entity_name
      entity_type
      in_requirement
      score
      verdict
      criteria { criterion_id name kind matched proof conditions { name met } }
      rules { name points hit reason }
      notes
    }
  }
`;

type Preview = IrDryRunPanelPreviewQuery$data['intelligenceRequirementPreview'];
type Test = IrDryRunPanelTestQuery$data['intelligenceRequirementTestEntity'];

const DEBOUNCE_MS = 1200;

// Runs the query a while after the last change of its key; an answer that arrives after a newer request is ignored
const useDebouncedQuery = <T, >(key: string | null, run: () => Promise<T>) => {
  const [result, setResult] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [running, setRunning] = useState(false);
  const request = useRef(0);
  useEffect(() => {
    if (key === null) {
      setResult(null);
      return undefined;
    }
    const id = request.current + 1;
    request.current = id;
    const timer = setTimeout(() => {
      setRunning(true);
      run()
        .then((r) => {
          if (request.current !== id) return;
          setResult(r);
          setError(null);
        })
        .catch((e) => {
          if (request.current === id) setError(e?.message ?? String(e));
        })
        .finally(() => {
          if (request.current === id) setRunning(false);
        });
    }, DEBOUNCE_MS);
    return () => clearTimeout(timer);
  }, [key]);
  return { result, error, running };
};

const Section = ({ title, children }: { title: string; children: React.ReactNode }) => (
  <Box sx={{ mb: 2 }}>
    <Text as="div" variant="content-caption" style={{ textTransform: 'uppercase', opacity: 0.7, marginBottom: 6 }}>{title}</Text>
    {children}
  </Box>
);

const Line = ({ label, value, detail, muted }: { label: string; value?: string; detail?: string | null; muted?: boolean }) => (
  <Box sx={{ py: 0.75, borderBottom: '1px solid', borderColor: 'divider', opacity: muted ? 0.6 : 1 }}>
    <Box sx={{ display: 'flex', gap: 1, alignItems: 'baseline' }}>
      <Text as="span" variant="content-compact" style={{ flex: 1, minWidth: 0 }}>{label}</Text>
      {value !== undefined && <Text as="span" variant="content-compact-bold">{value}</Text>}
    </Box>
    {detail && <Text as="div" variant="content-caption" style={{ opacity: 0.75 }}>{detail}</Text>}
  </Box>
);

type Translate = ReturnType<typeof useFormatter>['t_i18n'];

// What a criterion brings today, written in the reader's language from its kind and count (the server note is the fallback)
const criterionNote = (t_i18n: Translate, draft: IrCriterionDraft | undefined, count: number | null | undefined, fallback: string | null) => {
  if (!draft) return fallback;
  if (draft.kind === 'graph' && draft.from_in_requirement && draft.from_group_ids.length === 0) {
    return t_i18n('Second hop: counted once entities enter the requirement (their existing relationships are then backfilled).');
  }
  if (count === null || count === undefined) return fallback;
  if (draft.kind === 'graph') {
    return draft.from_in_requirement
      ? t_i18n('{count, plural, one {# matching relationship today, plus the second hop once entities enter.} other {# matching relationships today, plus the second hop once entities enter.}}', { values: { count } })
      : t_i18n('{count, plural, one {# matching relationship today.} other {# matching relationships today.}}', { values: { count } });
  }
  if (draft.kind === 'attribute' && draft.from_group_ids.length > 0) {
    return t_i18n('{count, plural, one {# member of its subject groups today (they enter when they are created or updated, and as soon as they become members).} other {# members of its subject groups today (they enter when they are created or updated, and as soon as they become members).}}', { values: { count } });
  }
  if (draft.kind === 'attribute') {
    return t_i18n('{count, plural, one {# matching entity today (they enter when they are created or updated).} other {# matching entities today (they enter when they are created or updated).}}', { values: { count } });
  }
  if (draft.kind === 'keywords') {
    return t_i18n('{count, plural, one {About # entity mentions these keywords today (full-text search, approximate).} other {About # entities mention these keywords today (full-text search, approximate).}}', { values: { count } });
  }
  return fallback;
};

const PreviewView = ({ preview, criteria }: { preview: Preview; criteria: readonly IrCriterionDraft[] }) => {
  const { t_i18n, n } = useFormatter();
  return (
    <>
      {preview.errors.length > 0 && (
        <Section title={t_i18n('To fix before saving')}>
          {preview.errors.map((e) => <Box key={e} sx={{ color: 'error.main', mb: 0.5 }}><Text as="div" variant="content-compact">{e}</Text></Box>)}
        </Section>
      )}
      <Section title={t_i18n('Starting points today')}>
        {preview.groups.length === 0 && <Text as="div" variant="content-caption">{t_i18n('No subject group yet.')}</Text>}
        {preview.groups.map((g) => {
          let value: string | undefined;
          if (g.kind === 'filter') value = g.matching_count === null || g.matching_count === undefined ? '…' : n(g.matching_count);
          else if (g.kind === 'list') value = n(g.entities.length);
          const detail = g.unresolved_ids.length > 0
            ? t_i18n('{count, plural, one {# entity not found} other {# entities not found}}', { values: { count: g.unresolved_ids.length } })
            : null;
          return <Line key={g.group_id} label={irGroupLabel(t_i18n, preview.groups.map((p) => ({ id: p.group_id, name: p.name })), g.group_id)} value={value} detail={g.kind === 'keywords' ? t_i18n('Keywords: searched in the texts as they arrive') : detail} />;
        })}
      </Section>
      <Section title={t_i18n('What each criterion brings today')}>
        {preview.criteria.length === 0 && <Text as="div" variant="content-caption">{t_i18n('No criterion yet.')}</Text>}
        {preview.criteria.map((c) => {
          const draft = criteria.find((d) => d.id === c.criterion_id);
          return (
            <Line
              key={c.criterion_id}
              label={c.name || c.criterion_id}
              value={c.today_count === null || c.today_count === undefined ? t_i18n('Not counted today') : n(c.today_count)}
              detail={[criterionNote(t_i18n, draft, c.today_count, c.note ?? null), ...c.warnings].filter((d) => !!d).join(' ') || null}
            />
          );
        })}
      </Section>
      {preview.warnings.length > 0 && (
        <Section title={t_i18n('Warnings')}>
          {preview.warnings.map((w) => <Text key={w} as="div" variant="content-caption" style={{ marginBottom: 4 }}>{w}</Text>)}
        </Section>
      )}
    </>
  );
};

// The verdict of the dry run in the reader's language, from the result and the modes of the draft criteria
const testVerdict = (t_i18n: Translate, test: Test, criteria: readonly IrCriterionDraft[]) => {
  if (test.criteria.length === 0) {
    return t_i18n('Not in the requirement: no criterion brings a {type}', { values: { type: t_i18n(`entity_${test.entity_type}`) } });
  }
  const eligible = test.criteria.filter((c) => c.matched && c.conditions.every((k) => k.met));
  if (!test.criteria.some((c) => c.matched)) return t_i18n('Not in the requirement: no criterion brings it today');
  if (!test.in_requirement || eligible.length === 0) {
    const unmet = test.criteria.flatMap((c) => (c.matched ? c.conditions : [])).find((k) => !k.met);
    return unmet
      ? t_i18n('Not in the requirement: “{condition}” is not met', { values: { condition: unmet.name } })
      : t_i18n('Not in the requirement: a condition of the scope is not met');
  }
  const proposedOnly = eligible.every((c) => criteria.find((d) => d.id === c.criterion_id)?.mode === 'propose');
  return proposedOnly
    ? t_i18n('Proposed for review, score {score}', { values: { score: test.score } })
    : t_i18n('In the requirement, score {score}', { values: { score: test.score } });
};

const TestView = ({ test, criteria }: { test: Test; criteria: readonly IrCriterionDraft[] }) => {
  const { t_i18n } = useFormatter();
  const hasKeywords = criteria.some((d) => d.kind === 'keywords' && test.criteria.some((c) => c.criterion_id === d.id));
  return (
    <Box>
      <Box sx={{ display: 'flex', gap: 1, alignItems: 'center', mb: 1 }}>
        <Chip label={test.in_requirement ? t_i18n('In') : t_i18n('Out')} severity={test.in_requirement ? 'low' : 'critical'} size="sm" />
        <Text as="span" variant="content-compact-bold">{testVerdict(t_i18n, test, criteria)}</Text>
      </Box>
      {test.criteria.map((c) => (
        <Box key={c.criterion_id} sx={{ py: 0.75, borderBottom: '1px solid', borderColor: 'divider', opacity: c.matched ? 1 : 0.6 }}>
          <ConditionStatus met={c.matched} name={c.name} />
          <Text as="div" variant="content-caption" style={{ opacity: 0.75 }}>{c.matched ? c.proof : t_i18n('Does not bring it today')}</Text>
          {c.conditions.map((k) => (
            <Box key={k.name} sx={{ pl: 1.5 }}><ConditionStatus met={k.met} name={k.name} /></Box>
          ))}
        </Box>
      ))}
      {test.rules.length > 0 && (
        <Box sx={{ mt: 1 }}>
          {test.rules.map((r) => (
            <Line key={r.name} label={r.name} value={r.hit ? `${r.points > 0 ? '+' : ''}${r.points}` : '0'} muted={!r.hit} />
          ))}
          <Line label={t_i18n('Score')} value={String(test.score)} />
        </Box>
      )}
      {hasKeywords && (
        <Text as="div" variant="content-caption" style={{ opacity: 0.7, marginTop: 8 }}>
          {t_i18n('Keywords are searched in the texts as they are stored today, in the entity and in up to 50 containers that contain it.')}
        </Text>
      )}
    </Box>
  );
};

interface IrDryRunPanelProps {
  draft: IrDraft;
  irId?: string;
}

const IrDryRunPanel = ({ draft, irId }: IrDryRunPanelProps) => {
  const { t_i18n } = useFormatter();
  const [entity, setEntity] = useState<IrEntityOption | null>(null);
  // Only the parts of the draft that the engine reads (not the name, the question or the inbox settings)
  const input = useMemo(() => draftToInput(draft), [draft]);
  const configKey = useMemo(
    () => JSON.stringify([input.ir_subject_groups, input.ir_scope_criteria, input.ir_relevance_rules]),
    [input],
  );
  const preview = useDebouncedQuery<Preview | null>(configKey, () => fetchQuery<IrDryRunPanelPreviewQuery>(environment, previewQuery, { input: input as never })
    .toPromise().then((r) => r?.intelligenceRequirementPreview ?? null));
  const test = useDebouncedQuery<Test | null>(entity ? `${configKey}|${entity.value}` : null, () => fetchQuery<IrDryRunPanelTestQuery>(environment, testQuery, {
    input: input as never,
    entityId: entity?.value ?? '',
    irId: irId ?? null,
  }).toPromise().then((r) => r?.intelligenceRequirementTestEntity ?? null));
  return (
    <Paper padding={16} style={{ position: 'sticky', top: 16, maxHeight: 'calc(100vh - 120px)', overflowY: 'auto' }}>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1.5 }}>
        <Text as="span" variant="title-sm">{t_i18n('Dry run')}</Text>
        <Box sx={{ flex: 1 }} />
        {(preview.running || test.running) && <Loader variant={LoaderVariant.inline} />}
      </Box>
      <Text as="div" variant="content-caption" style={{ opacity: 0.7, marginBottom: 16 }}>
        {t_i18n('What this configuration represents in the platform today. Updated as you edit; nothing is saved.')}
      </Text>
      {preview.error && <Box sx={{ color: 'error.main', mb: 1.5 }}><Text as="div" variant="content-caption">{preview.error}</Text></Box>}
      {preview.result && <PreviewView preview={preview.result} criteria={draft.criteria} />}
      <Section title={t_i18n('Test an entity')}>
        <IrEntityPicker
          value={entity ? [entity] : []}
          onChange={(value) => setEntity(value.length > 0 ? value[value.length - 1] : null)}
        />
        <Box sx={{ mt: 1.5 }}>
          {!entity && <Text as="div" variant="content-caption" style={{ opacity: 0.7 }}>{t_i18n('Pick an entity to see whether this configuration brings it in, and why.')}</Text>}
          {entity && test.error && <Box sx={{ color: 'error.main' }}><Text as="div" variant="content-caption">{test.error}</Text></Box>}
          {entity && test.result && <TestView test={test.result} criteria={draft.criteria} />}
        </Box>
      </Section>
    </Paper>
  );
};

export default IrDryRunPanel;
