import React, { useEffect, useMemo, useRef, useState } from 'react';
import { fetchQuery, graphql } from 'react-relay';
import { Chip, Paper, Text } from '@filigran/design-system';
import Box from '@mui/material/Box';
import { useFormatter } from '../../../../components/i18n';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { environment } from '../../../../relay/environment';
import { draftToInput, type IrDraft, type IrEntityOption } from './irConfigTypes';
import { IrEntityPicker } from './IrFields';
import type { IrDryRunPanelPreviewQuery, IrDryRunPanelPreviewQuery$data } from './__generated__/IrDryRunPanelPreviewQuery.graphql';
import type { IrDryRunPanelTestQuery, IrDryRunPanelTestQuery$data } from './__generated__/IrDryRunPanelTestQuery.graphql';

// Dry run of the configuration being written, next to the form: what each subject and criterion represents today,
// and the verdict of the configuration on an entity chosen by the analyst. Nothing is saved or written.

const previewQuery = graphql`
  query IrDryRunPanelPreviewQuery($input: IntelligenceRequirementInput!) {
    intelligenceRequirementPreview(input: $input) {
      valid
      errors
      warnings
      groups { id name kind matching_count unresolved_ids entities { id } }
      criteria { id name kind today_count note warnings }
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

const PreviewView = ({ preview }: { preview: Preview }) => {
  const { t_i18n, n } = useFormatter();
  return (
    <>
      {preview.errors.length > 0 && (
        <Section title={t_i18n('To fix before saving')}>
          {preview.errors.map((e) => <Text key={e} as="div" variant="content-compact" style={{ color: '#ff8a80', marginBottom: 4 }}>{e}</Text>)}
        </Section>
      )}
      <Section title={t_i18n('Starting points today')}>
        {preview.groups.length === 0 && <Text as="div" variant="content-caption">{t_i18n('No subject group yet.')}</Text>}
        {preview.groups.map((g) => {
          let value: string | undefined;
          if (g.kind === 'filter') value = g.matching_count === null || g.matching_count === undefined ? '…' : n(g.matching_count);
          else if (g.kind === 'list') value = n(g.entities.length);
          const detail = g.unresolved_ids.length > 0 ? `${g.unresolved_ids.length} ${t_i18n('entities not found')}` : null;
          return <Line key={g.id} label={g.name || g.id} value={value} detail={g.kind === 'keywords' ? t_i18n('Keywords: searched in the texts as they arrive') : detail} />;
        })}
      </Section>
      <Section title={t_i18n('What each criterion brings today')}>
        {preview.criteria.length === 0 && <Text as="div" variant="content-caption">{t_i18n('No criterion yet.')}</Text>}
        {preview.criteria.map((c) => (
          <Line
            key={c.id}
            label={c.name || c.id}
            value={c.today_count === null || c.today_count === undefined ? '—' : n(c.today_count)}
            detail={[c.note, ...c.warnings].filter((d) => !!d).join(' ') || null}
          />
        ))}
      </Section>
      {preview.warnings.length > 0 && (
        <Section title={t_i18n('Warnings')}>
          {preview.warnings.map((w) => <Text key={w} as="div" variant="content-caption" style={{ marginBottom: 4 }}>{w}</Text>)}
        </Section>
      )}
    </>
  );
};

const TestView = ({ test }: { test: Test }) => {
  const { t_i18n } = useFormatter();
  return (
    <Box>
      <Box sx={{ display: 'flex', gap: 1, alignItems: 'center', mb: 1 }}>
        <Chip label={test.in_requirement ? t_i18n('In') : t_i18n('Out')} severity={test.in_requirement ? 'low' : 'critical'} size="sm" />
        <Text as="span" variant="content-compact-bold">{test.verdict}</Text>
      </Box>
      {test.criteria.map((c) => (
        <Box key={c.criterion_id} sx={{ py: 0.75, borderBottom: '1px solid', borderColor: 'divider', opacity: c.matched ? 1 : 0.6 }}>
          <Text as="div" variant="content-compact">{`${c.matched ? '✓' : '·'} ${c.name}`}</Text>
          <Text as="div" variant="content-caption" style={{ opacity: 0.75 }}>{c.matched ? c.proof : t_i18n('Does not bring it today')}</Text>
          {c.conditions.map((k) => (
            <Text key={k.name} as="div" variant="content-caption" style={{ color: k.met ? undefined : '#ff8a80', paddingLeft: 12 }}>{`${k.met ? '✓' : '✗'} ${k.name}`}</Text>
          ))}
        </Box>
      ))}
      {test.rules.length > 0 && (
        <Box sx={{ mt: 1 }}>
          {test.rules.map((r) => (
            <Line key={r.name} label={`${r.hit ? '✓' : '·'} ${r.name}`} value={r.hit ? `${r.points > 0 ? '+' : ''}${r.points}` : '0'} muted={!r.hit} />
          ))}
          <Line label={t_i18n('Score')} value={String(test.score)} />
        </Box>
      )}
      {test.notes.map((note) => <Text key={note} as="div" variant="content-caption" style={{ opacity: 0.7, marginTop: 8 }}>{note}</Text>)}
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
      {preview.error && <Text as="div" variant="content-caption" style={{ color: '#ff8a80', marginBottom: 12 }}>{preview.error}</Text>}
      {preview.result && <PreviewView preview={preview.result} />}
      <Section title={t_i18n('Test an entity')}>
        <IrEntityPicker
          value={entity ? [entity] : []}
          onChange={(value) => setEntity(value.length > 0 ? value[value.length - 1] : null)}
        />
        <Box sx={{ mt: 1.5 }}>
          {!entity && <Text as="div" variant="content-caption" style={{ opacity: 0.7 }}>{t_i18n('Pick an entity to see whether this configuration brings it in, and why.')}</Text>}
          {entity && test.error && <Text as="div" variant="content-caption" style={{ color: '#ff8a80' }}>{test.error}</Text>}
          {entity && test.result && <TestView test={test.result} />}
        </Box>
      </Section>
    </Paper>
  );
};

export default IrDryRunPanel;
