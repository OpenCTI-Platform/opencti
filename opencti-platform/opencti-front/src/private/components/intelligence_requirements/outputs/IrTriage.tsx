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

import React, { useEffect, useState } from 'react';
import { Alert, Chip, Text } from '@filigran/design-system';
import Box from '@mui/material/Box';
import { useFormatter } from '../../../../components/i18n';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { type AgentOption, callAgent, fetchAgentsForIntent } from '../../../../utils/ai/agentApi';
import useIrAiGate from '../useIrAiGate';

// "Why is this of interest?": an XTM One agent (intent cti.pir_triage) reads one entity of the inbox in the context
// of the requirement and gives an opinion with a confidence level. Advice only: the analyst decides.

const INTENT = 'cti.pir_triage';

export interface IrTriageVerdict {
  verdict: 'relevant' | 'reject' | 'uncertain';
  confidence: 'high' | 'medium' | 'low';
  confidence_reason: string;
  summary: string;
  for: string[];
  against: string[];
  kiqs: string[];
  suggestion: string;
}

const VERDICT_CHIP: Record<string, { label: string; severity: 'low' | 'critical' | 'medium' }> = {
  relevant: { label: 'Relevant', severity: 'low' },
  reject: { label: 'To reject', severity: 'critical' },
  uncertain: { label: 'Uncertain', severity: 'medium' },
};

const strings = (value: unknown): string[] => (Array.isArray(value) ? value.filter((v) => typeof v === 'string') : []);

const parseVerdict = (content: string): IrTriageVerdict => {
  const text = content.trim().replace(/^```(?:json)?\s*/i, '').replace(/```\s*$/, '');
  const parsed = JSON.parse(text.slice(text.indexOf('{'), text.lastIndexOf('}') + 1));
  const r = parsed.response ?? parsed;
  return {
    verdict: ['relevant', 'reject', 'uncertain'].includes(r.verdict) ? r.verdict : 'uncertain',
    confidence: ['high', 'medium', 'low'].includes(r.confidence) ? r.confidence : 'low',
    confidence_reason: typeof r.confidence_reason === 'string' ? r.confidence_reason : '',
    summary: typeof r.summary === 'string' ? r.summary : '',
    for: strings(r.for),
    against: strings(r.against),
    kiqs: strings(r.kiqs),
    suggestion: typeof r.suggestion === 'string' ? r.suggestion : '',
  };
};

// The triage agent, when AI is usable and an agent is bound to the intent (looked up once per inbox)
export const useIrTriageAgent = () => {
  const { visible, xtmOneConfigured, termsPending, disabledReason } = useIrAiGate('Why is this of interest?');
  const usable = visible && xtmOneConfigured && !termsPending && !disabledReason;
  const [agent, setAgent] = useState<AgentOption | null>(null);
  useEffect(() => {
    if (usable) fetchAgentsForIntent(INTENT).then((found) => setAgent(found[0] ?? null));
  }, [usable]);
  return usable ? agent : null;
};

// One opinion: the agent reads the entity in the context of the requirement
export const runTriage = async (agent: AgentOption, irId: string, entityId: string): Promise<IrTriageVerdict> => {
  const answer = await callAgent(agent.slug, [
    'Mode: triage',
    `Requirement ID: ${irId}`,
    `Entity ID: ${entityId}`,
    'Answer in the language of the question of the requirement.',
  ].join('\n'));
  if (answer.status === 'error') throw new Error(answer.error ?? 'The agent returned an error.');
  return parseVerdict(answer.content);
};

export const useIrTriage = (irId: string, entityId: string | null | undefined, agent: AgentOption | null) => {
  const [verdict, setVerdict] = useState<IrTriageVerdict | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const run = async () => {
    if (!agent || !entityId) return;
    setLoading(true);
    setError(null);
    try {
      setVerdict(await runTriage(agent, irId, entityId));
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };
  return { available: !!agent && !!entityId, verdict, loading, error, run };
};

export const VERDICT_CHIPS = VERDICT_CHIP;

export const IrTriageCard = ({ verdict, loading, error }: { verdict: IrTriageVerdict | null; loading: boolean; error: string | null }) => {
  const { t_i18n } = useFormatter();
  if (loading) {
    return (
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, py: 0.5 }}>
        <Loader variant={LoaderVariant.inline} />
        <Text as="span" variant="content-caption">{t_i18n('The agent reads the entity in the context of the requirement…')}</Text>
      </Box>
    );
  }
  if (error) return <Alert severity="error" title={error} />;
  if (!verdict) return null;
  const chip = VERDICT_CHIP[verdict.verdict];
  const list = (title: string, items: string[]) => items.length > 0 && (
    <Box>
      <Text as="div" variant="content-caption" style={{ opacity: 0.7 }}>{title}</Text>
      <Box component="ul" sx={{ m: 0, pl: 2.5 }}>
        {items.map((item) => <li key={item}><Text as="span" variant="content-caption">{item}</Text></li>)}
      </Box>
    </Box>
  );
  return (
    <Box sx={{ border: '1px solid', borderColor: 'divider', borderRadius: 1, p: 1.5, display: 'flex', flexDirection: 'column', gap: 1 }}>
      <Box sx={{ display: 'flex', gap: 1, alignItems: 'center', flexWrap: 'wrap' }}>
        <Text as="span" variant="content-compact-bold">{t_i18n('AI opinion')}</Text>
        <Chip label={t_i18n(chip.label)} severity={chip.severity} />
        <Chip label={`${t_i18n('Confidence')}: ${t_i18n(verdict.confidence)}`} />
        {verdict.confidence_reason && <Text as="span" variant="content-caption" style={{ opacity: 0.8 }}>{verdict.confidence_reason}</Text>}
      </Box>
      {verdict.summary && <Text as="div" variant="content-compact">{verdict.summary}</Text>}
      <Box sx={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 1.5 }}>
        {list(t_i18n('For'), verdict.for)}
        {list(t_i18n('Against'), verdict.against)}
      </Box>
      {list(t_i18n('Key intelligence questions it helps answer'), verdict.kiqs)}
      {verdict.suggestion && <Text as="div" variant="content-caption" style={{ opacity: 0.8 }}>{`${t_i18n('Configuration hint')}: ${verdict.suggestion}`}</Text>}
      <Text as="div" variant="content-caption" style={{ opacity: 0.6 }}>{t_i18n('Generated by AI: advice only, you decide.')}</Text>
    </Box>
  );
};
