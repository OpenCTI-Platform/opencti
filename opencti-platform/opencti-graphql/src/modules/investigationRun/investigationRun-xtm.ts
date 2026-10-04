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

// Calls to the XTM One investigation engine, as the identity of the run
// (cross-platform JWT). Every call answers a typed result and never throws:
// the manager decides what an unavailable engine means for the run.

import nconf from 'nconf';
import xtmOneClient from '../xtm/one/xtm-one-client';
import { issueXtmJwt } from '../../domain/xtm-auth';
import { getHttpClient, getResponseError } from '../../utils/http-client';
import { logApp, PLATFORM_VERSION } from '../../config/conf';
import { AUTOMATION_MANAGER_USER } from '../../utils/access';
import type { AuthContext } from '../../types/user';
import { buildPlaybookAutomationContext, type AgentJwtUser } from '../playbook/components/ai-agent-shared';
import { ENGINE_DISABLED, ENGINE_NOT_CONFIGURED, ENGINE_UNAVAILABLE, ENGINE_UNREACHABLE, INVESTIGATION_DEFAULT_AGENT_SLUG, INVESTIGATION_INTENT } from './investigationRun-types';
import { parseEngineInvestigation, type EngineInvestigation } from './investigationRun-engine';

const ENGINE_TIMEOUT_MS = 30 * 1000;
const FEEDBACK_TIMEOUT_MS = 15 * 1000;
const ENGINE_BASE = '/api/v1/platform/investigations';

export interface InvestigationFeedbackPayload {
  agent_slug: string;
  run_id: string;
  subject: { id: string; entity_type: string; name: string };
  decisions: Array<Record<string, unknown>>;
}

export type EngineFailure = typeof ENGINE_NOT_CONFIGURED | typeof ENGINE_DISABLED | typeof ENGINE_UNAVAILABLE | typeof ENGINE_UNREACHABLE;

export type EngineResult<T> = { ok: true; value: T } | { ok: false; failure: EngineFailure; status: number | null; message: string };

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

const engineUrl = (): string | null => {
  const xtmOneUrl = nconf.get('xtm:xtm_one_url');
  return xtmOneUrl && xtmOneClient.isConfigured() ? xtmOneUrl : null;
};

// 403: XTM One does not run investigations (DEEP_INVESTIGATION off or the
// agentic gate closed); 404: an XTM One without the investigation routes.
const failureOf = (e: unknown, operation: string): { ok: false; failure: EngineFailure; status: number | null; message: string } => {
  const httpErr = getResponseError(e);
  const status = httpErr?.status ?? null;
  const detail = httpErr?.data?.detail ?? httpErr?.data?.message ?? (e as Error)?.message;
  const message = typeof detail === 'string' ? detail.slice(0, 500) : `Investigation engine call failed (${status ?? 'network'})`;
  let failure: EngineFailure = ENGINE_UNREACHABLE;
  if (status === 403) failure = ENGINE_DISABLED;
  if (status === 404) failure = ENGINE_UNAVAILABLE;
  logApp.warn('[CASE AUTOPILOT] Investigation engine call failed', { operation, status, detail: message });
  return { ok: false, failure, status, message };
};

const call = async <T>(
  jwtUser: AgentJwtUser,
  operation: string,
  run: (client: ReturnType<typeof getHttpClient>) => Promise<{ data: unknown }>,
  parse: (data: unknown) => T | null,
  draftId?: string | null,
): Promise<EngineResult<T>> => {
  const xtmOneUrl = engineUrl();
  if (!xtmOneUrl) {
    return { ok: false, failure: ENGINE_NOT_CONFIGURED, status: null, message: 'XTM One is not configured' };
  }
  try {
    const jwt = await issueXtmJwt(jwtUser, xtmOneUrl);
    // Every read the engine makes in OpenCTI for this run is scoped to its Draft.
    const headers = draftId ? { ...platformHeaders(jwt), 'opencti-draft-id': draftId } : platformHeaders(jwt);
    const client = getHttpClient({ baseURL: xtmOneUrl, responseType: 'json', headers });
    const response = await run(client);
    const value = parse(response.data);
    if (value === null) {
      return { ok: false, failure: ENGINE_UNREACHABLE, status: null, message: `Unexpected answer of the investigation engine (${operation})` };
    }
    return { ok: true, value };
  } catch (e: unknown) {
    return failureOf(e, operation);
  }
};

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

export const startInvestigation = (jwtUser: AgentJwtUser, body: Record<string, unknown>, draftId: string | null | undefined) => {
  return call<EngineInvestigation>(jwtUser, 'start', (client) => client.post(ENGINE_BASE, body, { timeout: ENGINE_TIMEOUT_MS }), parseEngineInvestigation, draftId);
};

export const getInvestigation = (jwtUser: AgentJwtUser, investigationId: string, draftId: string | null | undefined) => {
  return call<EngineInvestigation>(
    jwtUser,
    'get',
    (client) => client.get(`${ENGINE_BASE}/${encodeURIComponent(investigationId)}`, { timeout: ENGINE_TIMEOUT_MS }),
    parseEngineInvestigation,
    draftId,
  );
};

export const cancelInvestigation = (jwtUser: AgentJwtUser, investigationId: string) => {
  return call<boolean>(
    jwtUser,
    'cancel',
    (client) => client.post(`${ENGINE_BASE}/${encodeURIComponent(investigationId)}/cancel`, {}, { timeout: ENGINE_TIMEOUT_MS }),
    () => true,
  );
};

export interface EnginePackChoice {
  value: string;
  label: string;
  description: string | null;
}

export interface EnginePackOption {
  key: string;
  label: string;
  description: string | null;
  default: string | null;
  choices: EnginePackChoice[];
}

export interface EnginePack {
  slug: string;
  label: string;
  description: string | null;
  recommended: boolean;
  applicable_source_count: number;
  total_source_count: number;
  max_iterations: number | null;
  options: EnginePackOption[];
}

const text = (value: unknown, max = 500): string | null => (typeof value === 'string' && value.trim() ? value.trim().slice(0, max) : null);
const count = (value: unknown): number => (Number.isFinite(Number(value)) ? Math.max(0, Math.floor(Number(value))) : 0);

export const parseEnginePacks = (data: unknown): EnginePack[] | null => {
  const list = Array.isArray(data) ? data : (data && typeof data === 'object' ? (data as { packs?: unknown }).packs : null);
  if (!Array.isArray(list)) return null;
  return list.map((raw): EnginePack | null => {
    const pack = raw && typeof raw === 'object' ? raw as Record<string, unknown> : null;
    const slug = text(pack?.slug, 200);
    if (!pack || !slug) return null;
    const options = (Array.isArray(pack.options) ? pack.options : []).map((rawOption): EnginePackOption | null => {
      const option = rawOption && typeof rawOption === 'object' ? rawOption as Record<string, unknown> : null;
      const key = text(option?.key, 100);
      if (!option || !key) return null;
      const choices = (Array.isArray(option.choices) ? option.choices : []).map((rawChoice): EnginePackChoice | null => {
        const choice = rawChoice && typeof rawChoice === 'object' ? rawChoice as Record<string, unknown> : null;
        const value = text(choice?.value, 100);
        return choice && value ? { value, label: text(choice.label) ?? value, description: text(choice.description, 1000) } : null;
      }).filter((choice): choice is EnginePackChoice => choice !== null);
      return { key, label: text(option.label) ?? key, description: text(option.description, 1000), default: text(option.default, 100), choices };
    }).filter((option): option is EnginePackOption => option !== null);
    return {
      slug,
      label: text(pack.label) ?? slug,
      description: text(pack.description, 2000),
      recommended: pack.recommended === true,
      applicable_source_count: count(pack.applicable_source_count),
      total_source_count: count(pack.total_source_count),
      max_iterations: pack.max_iterations === undefined || pack.max_iterations === null ? null : count(pack.max_iterations),
      options,
    };
  }).filter((pack): pack is EnginePack => pack !== null);
};

export const listInvestigationPacks = (jwtUser: AgentJwtUser) => {
  return call<EnginePack[]>(jwtUser, 'packs', (client) => client.get(`${ENGINE_BASE}/packs`, { timeout: ENGINE_TIMEOUT_MS }), parseEnginePacks);
};

/**
 * Send analyst decisions to XTM One so the agent memory calibrates the next
 * runs of this platform. Best effort: the decisions are already stored on the
 * run, an XTM One without the endpoint (404) or unreachable is only logged.
 */
export const pushInvestigationFeedback = async (author: AgentJwtUser, payload: InvestigationFeedbackPayload): Promise<boolean> => {
  const xtmOneUrl = engineUrl();
  if (!xtmOneUrl || payload.decisions.length === 0) {
    return false;
  }
  try {
    const jwt = await issueXtmJwt(author, xtmOneUrl);
    const httpClient = getHttpClient({ baseURL: xtmOneUrl, responseType: 'json', headers: platformHeaders(jwt) });
    await httpClient.post(`${ENGINE_BASE}/feedback`, payload, { timeout: FEEDBACK_TIMEOUT_MS });
    return true;
  } catch (e: unknown) {
    const httpErr = getResponseError(e);
    logApp.warn('[CASE AUTOPILOT] Feedback not delivered to XTM One', { runId: payload.run_id, status: httpErr?.status, cause: (e as Error)?.message });
    return false;
  }
};
