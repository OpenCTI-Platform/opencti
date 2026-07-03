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
import { ForbiddenAccess } from '../../../config/errors';
import { AUTOMATION_MANAGER_USER, executionContext, SYSTEM_USER } from '../../../utils/access';
import { internalLoadById } from '../../../database/middleware-loader';
import { ENTITY_TYPE_USER } from '../../../schema/internalObject';
import { OPENCTI_ADMIN_UUID } from '../../../schema/general';
import type { AuthContext, AuthUser } from '../../../types/user';
import type { BasicStoreEntity } from '../../../types/store';
import type { StixBundle } from '../../../types/stix-2-1-common';
import type { ComponentDefinition } from '../playbook-types';

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
 * Identity whose email is embedded in the cross-platform JWT sent to
 * XTM One — the minimal shape required by ``issueXtmJwt``.
 */
export interface AgentJwtUser {
  id: string;
  user_email: string;
}

/**
 * Resolve the identity whose email is embedded in the cross-platform JWT
 * sent to XTM One. When the component is configured with an explicit
 * ``run_as`` user, the JWT is minted for that user so XTM One resolves a
 * matching local account and any write-back to OpenCTI is attributed to
 * a real, well-known user.
 *
 * When no run-as user is configured — or the run-as user cannot be
 * loaded — it falls back to the seeded platform admin
 * (``OPENCTI_ADMIN_UUID``), a real account that is always present in
 * the database with a resolvable email. The in-memory
 * ``AUTOMATION_MANAGER_USER`` / ``SYSTEM_USER`` identities are NOT
 * valid fallbacks: their placeholder emails ("AUTOMATION MANAGER" /
 * "SYSTEM") can never be resolved to an account on the XTM One side,
 * so a JWT minted for them is guaranteed to be useless.
 *
 * Returns ``null`` when no resolvable identity exists at all (the
 * seeded admin itself cannot be loaded) so callers skip the XTM One
 * interaction instead of sending a dead JWT.
 *
 * Executors call this ONCE and hand the resolved identity to both the
 * intent-binding pre-check (``isAgentBoundToIntent``) and the agent
 * call itself (``callXtmAgent``), so the catalog visibility check and
 * the actual invocation are guaranteed to run as the SAME XTM One
 * identity and the user is only looked up once per playbook step.
 */
export const resolveAgentJwtUser = async (
  runAsUserId?: string,
): Promise<AgentJwtUser | null> => {
  const candidateIds = runAsUserId && runAsUserId !== OPENCTI_ADMIN_UUID
    ? [runAsUserId, OPENCTI_ADMIN_UUID]
    : [OPENCTI_ADMIN_UUID];
  const context = executionContext('playbook_components');
  for (const targetUserId of candidateIds) {
    try {
      const user = await internalLoadById<BasicStoreEntity & { user_email?: string }>(
        context,
        SYSTEM_USER,
        targetUserId,
        { type: ENTITY_TYPE_USER },
      );
      if (user?.user_email) {
        return { id: user.id, user_email: user.user_email };
      }
      logApp.warn('[PLAYBOOK AI AGENT] JWT user not found or has no resolvable email, trying next fallback', { targetUserId, userFound: !!user });
    } catch (e: unknown) {
      logApp.warn('[PLAYBOOK AI AGENT] Failed to resolve JWT user, trying next fallback', {
        targetUserId,
        cause: e instanceof Error ? e.message : String(e),
      });
    }
  }
  logApp.error('[PLAYBOOK AI AGENT] No resolvable JWT identity (seeded admin cannot be loaded), skipping XTM One interaction', {
    runAsUserId,
  });
  return null;
};

/**
 * Runtime defense in depth: re-check that ``slug`` is currently bound to
 * the expected ``intent`` in the XTM One catalog before the executor
 * actually invokes the agent. AJV validation at playbook save time only
 * guards saves that go through the schema resolver — direct DB writes,
 * future bulk-import paths, or an agent that gets unbound from the
 * intent after save would otherwise let the executor run an arbitrary
 * agent under the caller's JWT.
 *
 * The catalog lookup runs as the SAME identity that ``callXtmAgent``
 * will mint the JWT for: the executor resolves it once with
 * ``resolveAgentJwtUser`` (run-as user, defaulting to the seeded
 * platform admin) and passes it to both calls. The XTM One catalog is
 * scoped per user, so checking with any other identity (previously the
 * placeholder ``AUTOMATION_MANAGER_USER``) makes the check fail closed
 * for agents that are bound to the intent but only visible to the
 * run-as user (e.g. group-shared, non-company-managed agents).
 *
 * Returns ``false`` (and logs a warning) on catalog failure / unknown
 * slug / unresolvable identity (``jwtUser`` null), so the executor
 * falls through to its safe terminal branch (``unmodified`` /
 * fire-and-wait) instead of calling the agent.
 */
export const isAgentBoundToIntent = async (
  intent: string,
  slug: string,
  jwtUser: AgentJwtUser | null,
): Promise<boolean> => {
  if (!slug) return false;
  if (!jwtUser) {
    // No resolvable identity — the agent call itself could not run
    // either, so fail closed without hitting XTM One.
    return false;
  }
  try {
    // The context user is only used to mint the outbound JWT — spread the
    // automation user to satisfy the AuthUser shape, but carry the resolved
    // identity so the catalog lookup matches the subsequent agent call.
    const context: AuthContext = {
      ...buildPlaybookAutomationContext(),
      user: { ...AUTOMATION_MANAGER_USER, id: jwtUser.id, user_email: jwtUser.user_email },
    };
    const agents = await xtmOneClient.listAgentsForIntent(context, intent);
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

// A ``run_as`` configuration as stored on a playbook node: the member
// picker saves a ``{ label, value }`` option object, while hand-written or
// imported configs may carry a raw id string (or nothing at all).
export type RunAsConfiguration = string | { label?: string; value?: string } | null;

/**
 * Normalize the component ``run_as`` configuration into a plain user id.
 * The playbook form stores the member-picker selection as a
 * ``{ label, value }`` option object, while hand-written / imported
 * configs may carry a raw id string. Returns undefined when no run-as
 * user is configured.
 */
export const resolveRunAsUserId = (
  runAs?: RunAsConfiguration,
): string | undefined => {
  if (!runAs) return undefined;
  if (typeof runAs === 'string') return runAs.trim() || undefined;
  return runAs.value?.trim() || undefined;
};

/**
 * Core predicate behind the AI-agent ``run_as`` guardrail. The agent runs
 * on behalf of the configured user (its email is embedded in the XTM One
 * JWT and any write-back to OpenCTI is attributed to that account), so a
 * playbook author must not be able to impersonate an arbitrary user.
 *
 * Returns ``true`` only for identities the author is allowed to act as:
 *  - an unset ``run_as`` (at runtime it falls back to the seeded platform
 *    admin, see ``resolveAgentJwtUser``),
 *  - the author themselves (the currently authenticated user), and
 *  - a service account (``user_service_account = true``), which exists
 *    precisely to carry automated, non-human activity.
 *
 * The target user is loaded with SYSTEM_USER so the decision depends only
 * on the nature of the account, not on the author's own visibility over
 * it, and the check fails closed (returns ``false``) when the target
 * cannot be loaded. The generic ``members`` query (used by the picker and
 * many other places) is left untouched.
 */
export const isRunAsUserAllowed = async (
  context: AuthContext,
  user: AuthUser,
  runAs?: RunAsConfiguration,
): Promise<boolean> => {
  const runAsUserId = resolveRunAsUserId(runAs);
  if (!runAsUserId || runAsUserId === user.id) {
    return true;
  }
  const target = await internalLoadById<BasicStoreEntity & { user_service_account?: boolean }>(
    context,
    SYSTEM_USER,
    runAsUserId,
    { type: ENTITY_TYPE_USER },
  );
  return target?.user_service_account === true;
};

/**
 * Throwing variant of {@link isRunAsUserAllowed}, used by the playbook
 * node save paths (add / replace / insert) where the value comes from the
 * constrained picker: anything else is a crafted call and is refused with
 * a ForbiddenAccess.
 */
export const assertRunAsUserAllowed = async (
  context: AuthContext,
  user: AuthUser,
  runAs?: RunAsConfiguration,
): Promise<void> => {
  if (await isRunAsUserAllowed(context, user, runAs)) {
    return;
  }
  throw ForbiddenAccess('The "run as" user must be yourself or a service account', { runAsUserId: resolveRunAsUserId(runAs) });
};

/**
 * Collect the ``run_as`` value carried by every node of a serialized
 * playbook definition. Nodes without a configuration, with an unparseable
 * configuration, or without a ``run_as`` are skipped. Used to apply the
 * guardrail to the paths that persist a whole definition at once (import,
 * duplicate, raw field patch) rather than a single node.
 */
const extractDefinitionRunAsValues = (playbookDefinition?: string | null): RunAsConfiguration[] => {
  if (!playbookDefinition) return [];
  let definition: ComponentDefinition;
  try {
    definition = JSON.parse(playbookDefinition) as ComponentDefinition;
  } catch {
    return [];
  }
  return (definition.nodes ?? [])
    .map((node) => {
      if (!node?.configuration) return null;
      try {
        const config = JSON.parse(node.configuration) as { run_as?: RunAsConfiguration };
        return config.run_as ?? null;
      } catch {
        return null;
      }
    })
    .filter((runAs) => runAs !== null);
};

/**
 * Reject (throw) when any node of a whole serialized playbook definition
 * carries a disallowed ``run_as``. Used by the raw ``playbookFieldPatch``
 * path which the editor never uses to set the definition but which is
 * exposed on the GraphQL API and could be abused by a crafted call.
 */
export const assertDefinitionRunAsAllowed = async (
  context: AuthContext,
  user: AuthUser,
  playbookDefinition?: string | null,
): Promise<void> => {
  await Promise.all(
    extractDefinitionRunAsValues(playbookDefinition)
      .map((runAs) => assertRunAsUserAllowed(context, user, runAs)),
  );
};

/**
 * Sanitize a whole serialized playbook definition so that none of its
 * nodes runs as a disallowed user: disallowed ``run_as`` values are reset
 * to the acting user (always an allowed target). Used by the paths that
 * persist a definition coming from outside the constrained editor - import
 * (foreign user ids) and duplicate (another author's run_as) - where a
 * hard failure would needlessly break a legitimate operation while reset
 * still guarantees no impersonation. Returns the original string when
 * nothing had to change (or when it cannot be parsed).
 */
export const sanitizeDefinitionRunAs = async (
  context: AuthContext,
  user: AuthUser,
  playbookDefinition?: string | null,
): Promise<string | null | undefined> => {
  if (!playbookDefinition) return playbookDefinition;
  let definition: ComponentDefinition;
  try {
    definition = JSON.parse(playbookDefinition) as ComponentDefinition;
  } catch {
    return playbookDefinition;
  }
  const selfOption = { label: user.name, value: user.id };
  const mutations = await Promise.all((definition.nodes ?? []).map(async (node) => {
    if (!node?.configuration) return false;
    let config: { run_as?: RunAsConfiguration };
    try {
      config = JSON.parse(node.configuration) as { run_as?: RunAsConfiguration };
    } catch {
      return false;
    }
    if (config.run_as === undefined || config.run_as === null) return false;
    if (await isRunAsUserAllowed(context, user, config.run_as)) return false;
    config.run_as = selfOption;
    node.configuration = JSON.stringify(config);
    return true;
  }));
  return mutations.some((changed) => changed) ? JSON.stringify(definition) : playbookDefinition;
};

/**
 * Synchronous, non-streaming call to XTM One Platform Chat. Returns the
 * raw assistant content or null when the call cannot complete (XTM One
 * not configured, network failure, non-success status). Errors are
 * logged but never thrown — playbook components are responsible for
 * deciding how to react (route to ``unmodified``, swallow at the end
 * of a chain, etc.) instead of crashing the whole run.
 *
 * The JWT is minted for the identity the executor resolved once with
 * ``resolveAgentJwtUser`` (configured ``run_as`` user, defaulting to the
 * seeded platform admin) — the same identity the intent-binding
 * pre-check ran as — so XTM One, and any subsequent write-back to
 * OpenCTI, sees the agent call as coming from that real account. When
 * no resolvable identity exists at all (``jwtUser`` null), the call is
 * skipped (a JWT minted for an in-memory placeholder user can never be
 * resolved by XTM One anyway).
 */
export const callXtmAgent = async (
  agentSlug: string,
  content: string,
  jwtUser: AgentJwtUser | null,
): Promise<string | null> => {
  const xtmOneUrl = nconf.get('xtm:xtm_one_url');
  if (!xtmOneUrl || !xtmOneClient.isConfigured()) {
    logApp.warn('[PLAYBOOK AI AGENT] XTM One is not configured, skipping agent call');
    return null;
  }
  if (!jwtUser) {
    // resolveAgentJwtUser already logged why no identity could be resolved.
    return null;
  }
  try {
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
