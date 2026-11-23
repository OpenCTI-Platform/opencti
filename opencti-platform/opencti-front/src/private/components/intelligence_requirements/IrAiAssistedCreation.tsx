/*
Copyright (c) 2021-2025 Filigran SAS

This file is part of the OpenCTI Enterprise Edition ("EE") and is
licensed under the OpenCTI Enterprise Edition License (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://github.com/OpenCTI-Platform/opencti/blob/master/LICENSE

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*/

import React, { useEffect, useRef, useState } from 'react';
import { fetchQuery, graphql } from 'react-relay';
import { useNavigate } from 'react-router';
import { Alert, Checkbox, Chip, Input, Menu, MenuContent, MenuItem, MenuTrigger, Paper, Text, Textarea } from '@filigran/design-system';
import Box from '@mui/material/Box';
import { AddOutlined, ArrowDropDownOutlined, ArrowDropUpOutlined } from '@mui/icons-material';
import { LogoXtmOneIcon } from 'filigran-icon';
import Button from '@common/button/Button';
import Drawer from '@components/common/drawer/Drawer';
import FiligranIcon from '@components/common/FiligranIcon';
import ValidateTermsOfUseDialog from '@components/settings/ValidateTermsOfUseDialog';
import { useFormatter } from '../../../components/i18n';
import Loader, { LoaderVariant } from '../../../components/Loader';
import { environment } from '../../../relay/environment';
import { type AgentOption, callAgent, callAgentStream, fetchAgentsForIntent } from '../../../utils/ai/agentApi';
import { IrSelect } from './configuration/IrFields';
import { inputToDraft, type IrEntityOption } from './configuration/irConfigTypes';
import { IR_KIQS_ENABLED } from './configuration/irConstants';
import useIrAiGate from './useIrAiGate';
import type { IrAiAssistedCreationPreviewQuery, IrAiAssistedCreationPreviewQuery$data } from './__generated__/IrAiAssistedCreationPreviewQuery.graphql';

// AI assisted creation of a requirement, in 3 steps the analyst validates one by one:
// 1. the question, sharpened by the agent; 2. the key intelligence questions; 3. a configuration grounded in the
// model and the data of the platform, checked by OpenCTI (preview) before it opens, unsaved, in the configuration screen.

const INTENT = 'cti.pir_builder';
// The analyst writes the request: the whole proposal follows its language, not the default AI language of the platform
const LANGUAGE_OF_REQUEST = 'Answer in the language of the analyst request (the same language as the request text).';

// Preview ids aliased out of `id` (see IrDryRunPanel): they are the subject group, criterion and entity ids
const previewQuery = graphql`
  query IrAiAssistedCreationPreviewQuery($input: IntelligenceRequirementInput!) {
    intelligenceRequirementPreview(input: $input) {
      valid
      errors
      warnings
      groups { group_id: id name kind matching_count unresolved_ids entities { entity_id: id name entity_type } }
      criteria { criterion_id: id name kind today_count note warnings }
    }
  }
`;

type Preview = IrAiAssistedCreationPreviewQuery$data['intelligenceRequirementPreview'];
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Json = Record<string, any>;

interface QuestionStep { name: string; question: string; description: string; priority: string; rationale: string }
interface KiqStep { text: string; why: string; checked: boolean }
interface ConfigStep { config: Json; explanations: { criterion_id: string; text: string }[]; summary: string; preview: Preview | null }

// The agent answers {"response": {...}}; tolerate code fences and text around the JSON
const parseAgentJson = (content: string): Json => {
  const text = content.trim().replace(/^```(?:json)?\s*/i, '').replace(/```\s*$/, '');
  const start = text.indexOf('{');
  const end = text.lastIndexOf('}');
  if (start < 0 || end <= start) throw new Error('The agent did not answer with JSON.');
  const parsed = JSON.parse(text.slice(start, end + 1));
  return parsed.response ?? parsed;
};

const StepTitle = ({ index, current, label, number = index }: { index: number; current: number; label: string; number?: number }) => (
  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, opacity: index === current ? 1 : 0.5 }}>
    <Chip label={String(number)} severity={index <= current ? 'info' : 'neutral'} />
    <Text as="span" variant={index === current ? 'content-base-bold' : 'content-base'}>{label}</Text>
  </Box>
);

const IrAiAssistedCreationContent = ({ agent, onClose }: { agent: AgentOption; onClose: () => void }) => {
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const [step, setStep] = useState(1);
  const [request, setRequest] = useState('');
  const [question, setQuestion] = useState<QuestionStep | null>(null);
  const [kiqs, setKiqs] = useState<KiqStep[]>([]);
  const [config, setConfig] = useState<ConfigStep | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [elapsed, setElapsed] = useState(0);
  const abortRef = useRef<AbortController | null>(null);

  useEffect(() => {
    if (!loading) return undefined;
    setElapsed(0);
    const timer = setInterval(() => setElapsed((s) => s + 1), 1000);
    return () => clearInterval(timer);
  }, [loading]);
  useEffect(() => () => abortRef.current?.abort(), []);

  const run = async <T, >(work: () => Promise<T>): Promise<T | null> => {
    setLoading(true);
    setError(null);
    try {
      return await work();
    } catch (e) {
      setError((e as Error).message);
      return null;
    } finally {
      setLoading(false);
    }
  };

  const ask = async (content: string) => {
    const answer = await callAgent(agent.slug, content);
    if (answer.status === 'error') throw new Error(answer.error ?? t_i18n('The agent returned an error.'));
    return parseAgentJson(answer.content);
  };

  const suggestQuestion = () => run(async () => {
    const response = await ask(`Mode: question\nRequest: ${request}\n${LANGUAGE_OF_REQUEST}`);
    setQuestion({
      name: response.name ?? '',
      question: response.question ?? request,
      description: response.description ?? '',
      priority: ['critical', 'high', 'medium', 'low'].includes(response.priority) ? response.priority : 'medium',
      rationale: response.rationale ?? '',
    });
  });

  const suggestKiqs = () => run(async () => {
    const response = await ask(`Mode: kiqs\nQuestion: ${question?.question}\nAnalyst request: ${request}\n${LANGUAGE_OF_REQUEST}`);
    setKiqs((response.kiqs ?? []).map((k: Json) => ({ text: k.text ?? '', why: k.why ?? '', checked: true })));
  });

  const buildConfiguration = () => run(async () => {
    abortRef.current?.abort();
    abortRef.current = new AbortController();
    const chosen = kiqs.filter((k) => k.checked && k.text.trim());
    const content = [
      'Mode: configuration',
      `Name: ${question?.name}`,
      `Question: ${question?.question}`,
      `Description: ${question?.description}`,
      `Priority: ${question?.priority}`,
      ...(IR_KIQS_ENABLED ? ['Key intelligence questions:', ...chosen.map((k) => `- ${k.text}`)] : []),
      `Analyst request: ${request}`,
      LANGUAGE_OF_REQUEST,
    ].join('\n');
    const answer = await callAgentStream(agent.slug, content, () => {}, abortRef.current.signal, true);
    if (answer.status === 'error') throw new Error(answer.error ?? t_i18n('The agent returned an error.'));
    const response = parseAgentJson(answer.content);
    if (!response.config) throw new Error(t_i18n('The agent did not return a configuration.'));
    const result = await fetchQuery<IrAiAssistedCreationPreviewQuery>(environment, previewQuery, { input: response.config as never }).toPromise();
    setConfig({ config: response.config, explanations: response.explanations ?? [], summary: response.summary ?? '', preview: result?.intelligenceRequirementPreview ?? null });
  });

  const openInConfiguration = () => {
    if (!config) return;
    const entities = new Map<string, IrEntityOption>();
    (config.preview?.groups ?? []).forEach((g) => g.entities.forEach((e) => entities.set(e.entity_id, { value: e.entity_id, label: e.name, type: e.entity_type })));
    const proposed = inputToDraft(config.config, entities);
    const draft = IR_KIQS_ENABLED ? proposed : { ...proposed, kiqs: [] };
    onClose();
    navigate('/dashboard/intelligence_requirements/new', { state: { aiDraft: draft, aiNotes: { summary: config.summary, explanations: config.explanations } } });
  };

  const goTo = (next: number, rebuild = false) => {
    setStep(next);
    if (next === 2 && kiqs.length === 0) suggestKiqs();
    if (next === 3 && (rebuild || !config)) {
      setConfig(null);
      buildConfiguration();
    }
  };

  const waiting = (message: string) => (
    <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, py: 3 }}>
      <Loader variant={LoaderVariant.inline} />
      <Text as="span" variant="content-base">{`${message} (${elapsed} s)`}</Text>
    </Box>
  );

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
      <Box sx={{ display: 'flex', gap: 3 }}>
        <StepTitle index={1} current={step} label={t_i18n('Question')} />
        {IR_KIQS_ENABLED && <StepTitle index={2} current={step} label={t_i18n('Key intelligence questions')} />}
        <StepTitle index={3} number={IR_KIQS_ENABLED ? 3 : 2} current={step} label={t_i18n('Configuration')} />
      </Box>
      {error && <Alert severity="error" title={error} />}

      {step === 1 && (
        <>
          <Textarea
            label={t_i18n('What do you want to monitor, and for which decision?')}
            placeholder={t_i18n('e.g. Track the actively exploited vulnerabilities affecting our systems and the actors exploiting them, to prioritise patching.')}
            value={request}
            onChange={(e) => setRequest(e.target.value)}
            rows={4}
          />
          <Box><Button disabled={!request.trim() || loading} onClick={suggestQuestion}>{question ? t_i18n('Suggest again') : t_i18n('Suggest a question')}</Button></Box>
          {loading && waiting(t_i18n('The agent sharpens the question'))}
          {question && !loading && (
            <Paper padding={16}>
              <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1.5 }}>
                {question.rationale && <Alert severity="ia" title={question.rationale} />}
                <Input label={t_i18n('Name')} value={question.name} onChange={(e) => setQuestion({ ...question, name: e.target.value })} />
                <Textarea label={t_i18n('Intelligence question')} value={question.question} onChange={(e) => setQuestion({ ...question, question: e.target.value })} rows={3} />
                <Textarea label={t_i18n('Description')} value={question.description} onChange={(e) => setQuestion({ ...question, description: e.target.value })} rows={2} />
                <IrSelect
                  label={t_i18n('Priority')}
                  value={question.priority}
                  options={['critical', 'high', 'medium', 'low'].map((p) => ({ value: p, label: t_i18n(p) }))}
                  onChange={(priority) => setQuestion({ ...question, priority })}
                  width={200}
                />
              </Box>
            </Paper>
          )}
          <Box sx={{ display: 'flex', justifyContent: 'flex-end' }}>
            <Button disabled={!question || !question.question.trim() || loading} onClick={() => (IR_KIQS_ENABLED ? goTo(2) : goTo(3, true))}>{IR_KIQS_ENABLED ? t_i18n('Next: key intelligence questions') : t_i18n('Next: configuration')}</Button>
          </Box>
        </>
      )}

      {step === 2 && (
        <>
          {loading && waiting(t_i18n('The agent proposes key intelligence questions'))}
          {!loading && kiqs.map((kiq, i) => (
            <Paper key={i} padding={16}>
              <Box sx={{ display: 'grid', gridTemplateColumns: '32px 1fr', gap: 1, alignItems: 'start' }}>
                <Box sx={{ pt: 1 }}>
                  <Checkbox checked={kiq.checked} onCheckedChange={(v) => setKiqs(kiqs.map((k, j) => (j === i ? { ...k, checked: v === true } : k)))} aria-label={t_i18n('Keep')} />
                </Box>
                <Box sx={{ display: 'flex', flexDirection: 'column', gap: 0.5 }}>
                  <Textarea value={kiq.text} onChange={(e) => setKiqs(kiqs.map((k, j) => (j === i ? { ...k, text: e.target.value } : k)))} rows={2} aria-label={t_i18n('Key intelligence question')} />
                  {kiq.why && <Text as="div" variant="content-caption" style={{ opacity: 0.7 }}>{kiq.why}</Text>}
                </Box>
              </Box>
            </Paper>
          ))}
          {!loading && (
            <Box sx={{ display: 'flex', gap: 1 }}>
              <Button variant="secondary" onClick={() => setKiqs([...kiqs, { text: '', why: '', checked: true }])}>{t_i18n('Add a KIQ')}</Button>
              <Button variant="tertiary" onClick={suggestKiqs}>{t_i18n('Suggest again')}</Button>
            </Box>
          )}
          <Box sx={{ display: 'flex', justifyContent: 'space-between' }}>
            <Button variant="secondary" disabled={loading} onClick={() => setStep(1)}>{t_i18n('Back')}</Button>
            <Button
              disabled={loading || !kiqs.some((k) => k.checked && k.text.trim())}
              onClick={() => goTo(3, true)}
            >{t_i18n('Next: configuration')}
            </Button>
          </Box>
        </>
      )}

      {step === 3 && (
        <>
          {loading && waiting(t_i18n('The agent reads the model, searches the platform and checks the configuration with OpenCTI. It takes about a minute'))}
          {config && !loading && (
            <>
              {config.summary && <Alert severity="ia" title={t_i18n('Proposal of the agent')} description={config.summary} />}
              {config.preview && !config.preview.valid && <Alert severity="error" title={t_i18n('OpenCTI rejects this configuration')} description={config.preview.errors.join(' · ')} />}
              {(config.preview?.warnings ?? []).map((w) => <Alert key={w} severity="warning" title={w} />)}
              <Text as="div" variant="content-compact-bold">{t_i18n('Subjects')}</Text>
              {(config.preview?.groups ?? []).map((g) => {
                const keywords: string[] = (config.config.ir_subject_groups ?? []).find((cg: Json) => cg.id === g.group_id)?.keywords ?? [];
                return (
                  <Box key={g.group_id} sx={{ display: 'flex', gap: 1, alignItems: 'center', flexWrap: 'wrap' }}>
                    <Text as="span" variant="content-compact">{`${g.name} (${t_i18n(g.kind)}${g.matching_count != null ? `, ${g.matching_count}` : ''})`}</Text>
                    {g.entities.slice(0, 8).map((e) => <Chip key={e.entity_id} label={e.name} severity="info" />)}
                    {keywords.map((k) => <Chip key={k} label={`#${k}`} />)}
                    {g.unresolved_ids.length > 0 && <Chip label={t_i18n('{count, plural, one {# not found} other {# not found}}', { values: { count: g.unresolved_ids.length } })} severity="high" />}
                  </Box>
                );
              })}
              <Text as="div" variant="content-compact-bold">{t_i18n('Scope criteria')}</Text>
              {(config.preview?.criteria ?? []).map((c) => (
                <Paper key={c.criterion_id} padding={16}>
                  <Box sx={{ display: 'flex', gap: 1, alignItems: 'center', mb: 0.5 }}>
                    <Text as="span" variant="content-compact-bold">{c.name}</Text>
                    <Chip label={c.today_count != null ? t_i18n('{count, plural, one {# today} other {# today}}', { values: { count: c.today_count } }) : t_i18n('second hop')} severity={c.today_count ? 'low' : 'neutral'} />
                  </Box>
                  <Text as="div" variant="content-caption">{config.explanations.find((e) => e.criterion_id === c.criterion_id)?.text ?? c.note ?? ''}</Text>
                  {c.warnings.map((w) => <Text key={w} as="div" variant="content-caption">{`⚠ ${w}`}</Text>)}
                </Paper>
              ))}
            </>
          )}
          <Box sx={{ display: 'flex', justifyContent: 'space-between' }}>
            <Button variant="secondary" disabled={loading} onClick={() => setStep(IR_KIQS_ENABLED ? 2 : 1)}>{t_i18n('Back')}</Button>
            <Box sx={{ display: 'flex', gap: 1 }}>
              <Button variant="tertiary" disabled={loading} onClick={buildConfiguration}>{t_i18n('Regenerate')}</Button>
              <Button disabled={loading || !config} onClick={openInConfiguration}>{t_i18n('Review in the configuration screen')}</Button>
            </Box>
          </Box>
        </>
      )}
    </Box>
  );
};

// The one create entry point of the list: "Create a requirement" opens a menu with the blank form and "Create with AI",
// so the toolbar keeps one button at every width.
const IrAiAssistedCreation = () => {
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const { visible, xtmOneConfigured, termsPending, disabledReason } = useIrAiGate('Create with AI');
  const [menuOpen, setMenuOpen] = useState(false);
  const [open, setOpen] = useState(false);
  const [termsOpen, setTermsOpen] = useState(false);
  const [agent, setAgent] = useState<AgentOption | null | undefined>(undefined);

  useEffect(() => {
    if (!open || !xtmOneConfigured) return;
    fetchAgentsForIntent(INTENT).then((found) => setAgent(found[0] ?? null));
  }, [open, xtmOneConfigured]);

  // The assistant needs an XTM One agent able to read the model and the data of the platform
  const reason = disabledReason ?? (xtmOneConfigured ? null : t_i18n('Create with AI needs XTM One.'));
  const closeThen = (action: () => void) => () => {
    setMenuOpen(false);
    action();
  };
  const createBlank = () => navigate('/dashboard/intelligence_requirements/new');
  // AI disabled on the platform: one plain button, no menu of a single entry
  if (!visible) {
    return <Button data-testid="create-intelligence-requirement-button" aria-label={t_i18n('Create a requirement')} onClick={createBlank}>{t_i18n('Create')}</Button>;
  }
  return (
    <>
      <Menu open={menuOpen} onOpenChange={setMenuOpen} modal={false}>
        <MenuTrigger asChild>
          <Button
            data-testid="create-intelligence-requirement-button"
            aria-label={t_i18n('Create a requirement')}
            endIcon={menuOpen ? <ArrowDropUpOutlined /> : <ArrowDropDownOutlined />}
          >
            {t_i18n('Create')}
          </Button>
        </MenuTrigger>
        <MenuContent align="end" sideOffset={6} style={{ minWidth: 280 }}>
          <MenuItem startIcon={<AddOutlined fontSize="small" />} onSelect={closeThen(createBlank)}>
            {t_i18n('Blank requirement')}
          </MenuItem>
          <MenuItem
            startIcon={<FiligranIcon icon={LogoXtmOneIcon} size={16} />}
            disabled={!!reason}
            onSelect={closeThen(() => (termsPending ? setTermsOpen(true) : setOpen(true)))}
          >
            <span style={{ display: 'flex', flexDirection: 'column', gap: 2, padding: '4px 0' }}>
              <span>{t_i18n('Create with AI')}</span>
              {reason && <Text as="span" variant="content-compact">{reason}</Text>}
            </span>
          </MenuItem>
        </MenuContent>
      </Menu>
      {termsOpen && <ValidateTermsOfUseDialog open={termsOpen} onClose={() => setTermsOpen(false)} />}
      {/* The drawer clones its single child: keep one */}
      <Drawer open={open} onClose={() => setOpen(false)} title={t_i18n('Create with AI')} size="large">
        <>
          {open && agent === undefined && <Loader variant={LoaderVariant.inElement} />}
          {open && agent === null && <Alert severity="warning" title={t_i18n('No agent available')} description={t_i18n('Bind an XTM One agent to the cti.pir_builder intent.')} />}
          {open && agent && <IrAiAssistedCreationContent agent={agent} onClose={() => setOpen(false)} />}
        </>
      </Drawer>
    </>
  );
};

export default IrAiAssistedCreation;
