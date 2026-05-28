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
import xtmOneClient from '../../xtm/one/xtm-one-client';
import { issueXtmJwt } from '../../../domain/xtm-auth';
import { getHttpClient, getResponseError } from '../../../utils/http-client';
import { logApp, PLATFORM_VERSION } from '../../../config/conf';
import { executionContext, SYSTEM_USER } from '../../../utils/access';
import { getEntitiesMapFromCache } from '../../../database/cache';
import { ENTITY_TYPE_USER } from '../../../schema/internalObject';
import { OPENCTI_ADMIN_UUID } from '../../../schema/general';
import { UnsupportedError } from '../../../config/errors';
import type { AuthContext, AuthUser } from '../../../types/user';
import type { StixBundle } from '../../../types/stix-2-1-common';

// 5 minutes — agent runs may take a while when the LLM has to materialise
// a large STIX bundle or call multiple tools. Keep well above the default
// 2-minute httpClient cap used by the chatbot proxy.
export const AGENT_CALL_TIMEOUT_MS = 5 * 60 * 1000;

/**
 * Resolve the platform admin user from the user cache. Playbooks run as
 * automation but the JWT we mint must roundtrip — XTM One agents call
 * back into OpenCTI through the same JWT (e.g. via the OpenCTI
 * integration), and OpenCTI's incoming-JWT auth requires the email
 * claim to match an existing user. The platform admin is guaranteed to
 * exist (created at platform init) so it is the natural identity for
 * automated agent calls.
 */
export const getPlaybookAutomationUser = async (
  context: AuthContext,
): Promise<AuthUser> => {
  const usersMap = await getEntitiesMapFromCache<AuthUser>(context, SYSTEM_USER, ENTITY_TYPE_USER);
  const admin = usersMap.get(OPENCTI_ADMIN_UUID);
  if (!admin || !admin.user_email) {
    throw UnsupportedError('Cannot resolve platform admin user for playbook agent call');
  }
  return admin;
};

export const buildPlaybookAutomationContext = async (): Promise<AuthContext> => {
  const context = executionContext('playbook_components');
  const user = await getPlaybookAutomationUser(context);
  return { ...context, user };
};

/**
 * Combine an optional natural-language instruction with the JSON
 * representation of the bundle into the single ``content`` payload sent
 * to the agent. Both AI-agent playbook components share this contract
 * so agents bound to either intent can be authored once.
 */
export const buildAgentMessageContent = (bundle: StixBundle, userPrompt?: string): string => {
  const instruction = (userPrompt ?? '').trim();
  const bundleJson = JSON.stringify(bundle, null, 2);
  if (!instruction) {
    return `--- STIX BUNDLE ---\n${bundleJson}`;
  }
  return `${instruction}\n\n--- STIX BUNDLE ---\n${bundleJson}`;
};

/**
 * Resolve the dynamic ``oneOf`` list of agents bound to ``intent`` so
 * the playbook form can render the agent picker. Returns an empty list
 * (and logs a warning) when XTM One is unreachable, the platform admin
 * cannot be resolved, or the catalog call itself fails — so the form
 * still renders cleanly instead of failing the whole resolver.
 */
export const buildAgentSlugOneOf = async (
  intent: string,
): Promise<Array<{ const: string; title: string }>> => {
  let agents: Awaited<ReturnType<typeof xtmOneClient.listAgentsForIntent>> = [];
  try {
    const automationContext = await buildPlaybookAutomationContext();
    agents = await xtmOneClient.listAgentsForIntent(automationContext, intent);
  } catch (e: unknown) {
    logApp.warn('[PLAYBOOK AI AGENT] Failed to load agent catalog', {
      intent,
      cause: (e as Error).message,
    });
  }
  return (agents ?? [])
    .filter((a) => !!a.agent_slug)
    .map((a) => ({ const: a.agent_slug as string, title: a.agent_name }))
    .sort((a, b) => (a.title.toLowerCase() > b.title.toLowerCase() ? 1 : -1));
};

/**
 * Synchronous, non-streaming call to XTM One Platform Chat. Returns the
 * raw assistant content or null when the call cannot complete (XTM One
 * not configured, admin user unresolvable, network failure, non-success
 * status). Errors are logged but never thrown — playbook components are
 * responsible for deciding how to react (route to ``unmodified``,
 * swallow at the end of a chain, etc.) instead of crashing the whole
 * run.
 *
 * The JWT is minted on behalf of the platform admin so that it survives
 * the round-trip when the agent calls back into OpenCTI through the
 * OpenCTI integration: OpenCTI's incoming JWT auth resolves the email
 * claim against an existing user, so a synthetic identity would fail.
 */
export const callXtmAgent = async (
  agentSlug: string,
  content: string,
): Promise<string | null> => {
  const xtmOneUrl = nconf.get('xtm:xtm_one_url');
  if (!xtmOneUrl || !xtmOneClient.isConfigured()) {
    logApp.warn('[PLAYBOOK AI AGENT] XTM One is not configured, skipping agent call');
    return null;
  }
  try {
    const context = executionContext('playbook_components');
    const adminUser = await getPlaybookAutomationUser(context);
    const jwt = await issueXtmJwt(adminUser, xtmOneUrl);
    const httpClient = getHttpClient({
      baseURL: xtmOneUrl,
      responseType: 'json',
      headers: {
        Authorization: `Bearer ${jwt}`,
        'Content-Type': 'application/json',
        'X-Platform-Product': 'opencti',
        'X-Platform-Version': PLATFORM_VERSION,
      },
    });
    const response = await httpClient.post(
      '/api/v1/platform/chat/messages',
      { agent_slug: agentSlug, content, stream: false },
      { timeout: AGENT_CALL_TIMEOUT_MS },
    );
    return response.data?.content ?? null;
  } catch (e: unknown) {
    const httpErr = getResponseError(e);
    const detail = httpErr?.data?.detail ?? httpErr?.data?.message ?? (e as Error)?.message;
    logApp.error('[PLAYBOOK AI AGENT] Agent call failed', {
      agentSlug,
      status: httpErr?.status,
      detail,
    });
    return null;
  }
};
