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
import { AUTOMATION_MANAGER_USER, executionContext, SYSTEM_USER } from '../../../utils/access';
import { internalLoadById } from '../../../database/middleware-loader';
import { ENTITY_TYPE_USER } from '../../../schema/internalObject';
import { OPENCTI_ADMIN_UUID } from '../../../schema/general';
import type { AuthContext } from '../../../types/user';
import type { BasicStoreEntity } from '../../../types/store';
import type { StixBundle } from '../../../types/stix-2-1-common';

// 5 minutes — agent runs may take a while when the LLM has to materialise
// a large STIX bundle or call multiple tools. Keep well above the default
// 2-minute httpClient cap used by the chatbot proxy.
export const AGENT_CALL_TIMEOUT_MS = 5 * 60 * 1000;

/**
 * Identity used by the AI-agent playbook components to call XTM One.
 * Reuses the existing platform-internal automation user so the JWT we
 * mint carries a stable, well-known subject across every playbook run.
 */
export const buildPlaybookAutomationContext = (): AuthContext => {
  const context = executionContext('playbook_components');
  return { ...context, user: AUTOMATION_MANAGER_USER };
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
 * (and logs a warning) when XTM One is unreachable or the catalog call
 * itself fails — so the form still renders cleanly instead of failing
 * the whole resolver.
 */
export const buildAgentSlugOneOf = async (
  intent: string,
): Promise<Array<{ const: string; title: string }>> => {
  let agents: Awaited<ReturnType<typeof xtmOneClient.listAgentsForIntent>> = [];
  try {
    agents = await xtmOneClient.listAgentsForIntent(buildPlaybookAutomationContext(), intent);
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
 * Runtime defense in depth: re-check that ``slug`` is currently bound to
 * the expected ``intent`` in the XTM One catalog before the executor
 * actually invokes the agent. AJV validation at playbook save time only
 * guards saves that go through the schema resolver — direct DB writes,
 * future bulk-import paths, or an agent that gets unbound from the
 * intent after save would otherwise let the executor run an arbitrary
 * agent under the platform-internal ``AUTOMATION_MANAGER_USER`` JWT.
 *
 * Returns ``false`` (and logs a warning) on catalog failure / unknown
 * slug, so the executor falls through to its safe terminal branch
 * (``unmodified`` / fire-and-wait) instead of calling the agent.
 */
export const isAgentBoundToIntent = async (
  intent: string,
  slug: string,
): Promise<boolean> => {
  if (!slug) return false;
  try {
    const agents = await xtmOneClient.listAgentsForIntent(buildPlaybookAutomationContext(), intent);
    return (agents ?? []).some((a) => a.agent_slug === slug);
  } catch (e: unknown) {
    logApp.warn('[PLAYBOOK AI AGENT] Failed to validate agent intent binding', {
      intent,
      slug,
      cause: (e as Error).message,
    });
    return false;
  }
};

/**
 * Normalize the component ``run_as`` configuration into a plain user id.
 * The playbook form stores the member-picker selection as a
 * ``{ label, value }`` option object, while hand-written / imported
 * configs may carry a raw id string. Returns undefined when no run-as
 * user is configured.
 */
export const resolveRunAsUserId = (
  runAs?: string | { label?: string; value?: string } | null,
): string | undefined => {
  if (!runAs) return undefined;
  if (typeof runAs === 'string') return runAs.trim() || undefined;
  return runAs.value?.trim() || undefined;
};

/**
 * Resolve the identity whose email is embedded in the cross-platform JWT
 * sent to XTM One. When the component is configured with an explicit
 * ``run_as`` user, the JWT is minted for that user so XTM One resolves a
 * matching local account and any write-back to OpenCTI is attributed to
 * a real, well-known user.
 *
 * When no run-as user is configured, it defaults to the seeded platform
 * admin (``OPENCTI_ADMIN_UUID``) - a real, indexed account with a
 * resolvable email - rather than the in-memory ``AUTOMATION_MANAGER_USER``,
 * whose placeholder email cannot be resolved on the XTM One side.
 *
 * ``AUTOMATION_MANAGER_USER`` remains the last-resort fallback when the
 * target user (explicit run-as or seeded admin) cannot be loaded, so the
 * component degrades gracefully instead of failing.
 */
const resolveAgentJwtUser = async (
  runAsUserId?: string,
): Promise<{ id: string; user_email: string }> => {
  const targetUserId = runAsUserId || OPENCTI_ADMIN_UUID;
  try {
    const context = executionContext('playbook_components');
    const user = await internalLoadById<BasicStoreEntity & { user_email?: string }>(
      context,
      SYSTEM_USER,
      targetUserId,
      { type: ENTITY_TYPE_USER },
    );
    if (user?.user_email) {
      return { id: user.id, user_email: user.user_email };
    }
    logApp.warn('[PLAYBOOK AI AGENT] Run-as user not found, falling back to automation user', { runAsUserId: targetUserId });
  } catch (e: unknown) {
    logApp.warn('[PLAYBOOK AI AGENT] Failed to resolve run-as user, falling back to automation user', {
      runAsUserId: targetUserId,
      cause: (e as Error).message,
    });
  }
  return AUTOMATION_MANAGER_USER;
};

/**
 * Synchronous, non-streaming call to XTM One Platform Chat. Returns the
 * raw assistant content or null when the call cannot complete (XTM One
 * not configured, network failure, non-success status). Errors are
 * logged but never thrown — playbook components are responsible for
 * deciding how to react (route to ``unmodified``, swallow at the end
 * of a chain, etc.) instead of crashing the whole run.
 *
 * The JWT is minted on behalf of the configured ``run_as`` user (see
 * ``resolveAgentJwtUser``) so XTM One - and any subsequent write-back to
 * OpenCTI - sees the agent call as coming from that real account. When no
 * run-as user is configured it defaults to the seeded platform admin.
 */
export const callXtmAgent = async (
  agentSlug: string,
  content: string,
  runAsUserId?: string,
): Promise<string | null> => {
  const xtmOneUrl = nconf.get('xtm:xtm_one_url');
  if (!xtmOneUrl || !xtmOneClient.isConfigured()) {
    logApp.warn('[PLAYBOOK AI AGENT] XTM One is not configured, skipping agent call');
    return null;
  }
  try {
    const jwtUser = await resolveAgentJwtUser(runAsUserId);
    const jwt = await issueXtmJwt(jwtUser, xtmOneUrl);
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
