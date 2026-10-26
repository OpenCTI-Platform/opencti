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

import type { AuthContext, AuthUser } from '../../types/user';
import { logApp } from '../../config/conf';
import { editInternalObject } from '../../domain/internalObject';
import xtmOneClient from '../xtm/one/xtm-one-client';
import { callXtmAgent, isXtmOneConfigured, resolveAgentJwtUser } from '../playbook/components/ai-agent-shared';
import { type BasicStoreEntityIntelligenceRequirement, ENTITY_TYPE_INTELLIGENCE_REQUIREMENT, type StoreEntityIntelligenceRequirement } from './intelligenceRequirement-types';
import { createItem } from './intelligenceRequirementItem-domain';

// Recurring AI brief of a requirement: an XTM One agent (intent cti.pir_insight) reads the requirement with its tools
// and writes a short brief, delivered as an inbox item. Generated server-side, as the creator of the requirement
// (or the platform admin), at the frequency of the requirement or on demand.

const INTENT = 'cti.pir_insight';
const DAY = 24 * 3600 * 1000;
const PERIODS: Record<string, number> = { daily: DAY, weekly: 7 * DAY };

export const isBriefDue = (ir: BasicStoreEntityIntelligenceRequirement, now = Date.now()) => {
  const period = PERIODS[ir.ir_brief_frequency ?? 'off'];
  if (!period) return false;
  const last = ir.ir_last_brief_at ? new Date(ir.ir_last_brief_at).getTime() : 0;
  return now - last >= period;
};

export const markBriefStarted = async (context: AuthContext, user: AuthUser, irId: string) => {
  return editInternalObject<StoreEntityIntelligenceRequirement>(context, user, irId, ENTITY_TYPE_INTELLIGENCE_REQUIREMENT, [
    { key: 'ir_last_brief_at', value: [new Date().toISOString()] },
  ], { auditLogEnabled: false });
};

const briefPrompt = (ir: BasicStoreEntityIntelligenceRequirement, label: string) => {
  const since = ir.ir_last_brief_at ? new Date(ir.ir_last_brief_at).toISOString().slice(0, 10) : null;
  return [
    `Write the ${label} brief of the OpenCTI intelligence requirement with ID ${ir.id} ("${ir.name}").`,
    since
      ? `Focus on what changed since ${since}: entities that entered or were proposed, scores that crossed a threshold, analyst decisions, health alerts.`
      : 'It is the first brief: give the current state of the requirement.',
    'Keep it short and in this order: an executive summary (3 bullet points), what changed, one line per key intelligence question (answered, partly answered or gap), recommended next steps.',
    'Answer in the language of the question of the requirement.',
  ].join('\n');
};

/**
 * Generate a brief and add it to the inbox. Returns the inbox item, or null when XTM One, the identity or the agent is missing.
 */
export const generateRequirementBrief = async (context: AuthContext, user: AuthUser, ir: BasicStoreEntityIntelligenceRequirement, trigger: 'scheduled' | 'manual') => {
  if (!isXtmOneConfigured()) return null;
  const creatorId = Array.isArray(ir.creator_id) ? ir.creator_id[0] : ir.creator_id;
  const jwtUser = await resolveAgentJwtUser(creatorId as string | undefined);
  if (!jwtUser) return null;
  const agents = await xtmOneClient.listAgentsForIntent({ ...context, user: jwtUser as unknown as AuthUser }, INTENT);
  const agent = agents[0];
  if (!agent) {
    logApp.warn('[OPENCTI-MODULE] No XTM One agent for the intelligence requirement brief', { intent: INTENT, requirement: ir.id });
    return null;
  }
  const label = trigger === 'scheduled' ? (ir.ir_brief_frequency ?? 'weekly') : 'on demand';
  const content = await callXtmAgent(agent.agent_slug, briefPrompt(ir, label), jwtUser);
  if (!content) return null;
  const date = new Date().toISOString().slice(0, 10);
  const title = `${trigger === 'scheduled' ? `${label.charAt(0).toUpperCase()}${label.slice(1)} brief` : 'Brief'} · ${date}`;
  return createItem(context, user, ir.id, 'brief', title, { data: { content: content.replace(/^```(?:html)?\s*/i, '').replace(/```\s*$/, '').trim() } });
};
