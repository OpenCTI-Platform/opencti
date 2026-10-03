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

import nconf from 'nconf';
import xtmOneClient from '../xtm/one/xtm-one-client';
import { issueXtmJwt } from '../../domain/xtm-auth';
import { getHttpClient, getResponseError } from '../../utils/http-client';
import { logApp, PLATFORM_VERSION } from '../../config/conf';
import { AUTOMATION_MANAGER_USER } from '../../utils/access';
import type { AuthContext } from '../../types/user';
import { AGENT_CALL_TIMEOUT_MS, buildPlaybookAutomationContext, type AgentJwtUser } from '../playbook/components/ai-agent-shared';
import { INVESTIGATION_DEFAULT_AGENT_SLUG, INVESTIGATION_INTENT } from './investigationRun-types';

const FEEDBACK_TIMEOUT_MS = 15 * 1000;

export interface InvestigationAgentAnswer {
  content: string | null;
  error: string | null;
}

export interface InvestigationFeedbackPayload {
  agent_slug: string;
  run_id: string;
  subject: { id: string; entity_type: string; name: string };
  decisions: Array<Record<string, unknown>>;
}

const contextFor = (jwtUser: AgentJwtUser): AuthContext => ({
  ...buildPlaybookAutomationContext(),
  user: { ...AUTOMATION_MANAGER_USER, id: jwtUser.id, user_email: jwtUser.user_email },
});

const platformHeaders = (jwt: string): Record<string, string> => ({
  Authorization: `Bearer ${jwt}`,
  'Content-Type': 'application/json',
  'X-Platform-Product': 'opencti',
  'X-Platform-Version': PLATFORM_VERSION,
});

/**
 * Pick the agent bound to the investigation intent, as seen by the run's
 * identity (the catalog is scoped per user). A policy may pin an agent: it is
 * only used while it is still bound to the intent, so a crafted or stale
 * configuration can never run an arbitrary agent.
 */
export const resolveInvestigationAgent = async (jwtUser: AgentJwtUser, pinnedSlug?: string | null): Promise<string | null> => {
  const agents = await xtmOneClient.listAgentsForIntent(contextFor(jwtUser), INVESTIGATION_INTENT);
  const slugs = (agents ?? []).map((agent) => agent.agent_slug).filter((slug): slug is string => !!slug);
  if (pinnedSlug) {
    return slugs.includes(pinnedSlug) ? pinnedSlug : null;
  }
  if (slugs.includes(INVESTIGATION_DEFAULT_AGENT_SLUG)) {
    return INVESTIGATION_DEFAULT_AGENT_SLUG;
  }
  // The catalog is ordered by priority, highest first.
  return slugs[0] ?? null;
};

/**
 * Non-streaming call to the Case Autopilot agent. The draft header scopes
 * every OpenCTI tool the agent calls to the run's Draft, so its reads see the
 * enrichment results and its writes never reach the live graph. Never throws.
 */
export const callInvestigationAgent = async (
  agentSlug: string,
  content: string,
  jwtUser: AgentJwtUser,
  draftId: string | null | undefined,
): Promise<InvestigationAgentAnswer> => {
  const xtmOneUrl = nconf.get('xtm:xtm_one_url');
  if (!xtmOneUrl || !xtmOneClient.isConfigured()) {
    return { content: null, error: 'XTM One is not configured' };
  }
  try {
    const jwt = await issueXtmJwt(jwtUser, xtmOneUrl);
    const httpClient = getHttpClient({
      baseURL: xtmOneUrl,
      responseType: 'json',
      headers: { ...platformHeaders(jwt), 'opencti-draft-id': draftId ?? '' },
    });
    const response = await httpClient.post(
      '/api/v1/platform/chat/messages',
      { agent_slug: agentSlug, content, stream: false },
      { timeout: AGENT_CALL_TIMEOUT_MS },
    );
    const answer = response.data?.content;
    return typeof answer === 'string' && answer.trim().length > 0
      ? { content: answer, error: null }
      : { content: null, error: 'The agent returned an empty answer' };
  } catch (e: unknown) {
    const httpErr = getResponseError(e);
    const detail = httpErr?.data?.detail ?? httpErr?.data?.message ?? (e as Error)?.message;
    logApp.warn('[CASE AUTOPILOT] Agent call failed', { agentSlug, status: httpErr?.status, detail });
    return { content: null, error: typeof detail === 'string' ? detail.slice(0, 500) : `Agent call failed (${httpErr?.status ?? 'network'})` };
  }
};

/**
 * Send analyst decisions to XTM One so the agent memory calibrates the next
 * runs of this platform. Best effort: the decisions are already stored on the
 * run, an XTM One without the endpoint (404) or unreachable is only logged.
 */
export const pushInvestigationFeedback = async (author: AgentJwtUser, payload: InvestigationFeedbackPayload): Promise<boolean> => {
  const xtmOneUrl = nconf.get('xtm:xtm_one_url');
  if (!xtmOneUrl || !xtmOneClient.isConfigured() || payload.decisions.length === 0) {
    return false;
  }
  try {
    const jwt = await issueXtmJwt(author, xtmOneUrl);
    const httpClient = getHttpClient({ baseURL: xtmOneUrl, responseType: 'json', headers: platformHeaders(jwt) });
    await httpClient.post('/api/v1/platform/investigations/feedback', payload, { timeout: FEEDBACK_TIMEOUT_MS });
    return true;
  } catch (e: unknown) {
    const httpErr = getResponseError(e);
    logApp.warn('[CASE AUTOPILOT] Feedback not delivered to XTM One', { runId: payload.run_id, status: httpErr?.status, cause: (e as Error)?.message });
    return false;
  }
};
