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

import * as R from 'ramda';
import nconf from 'nconf';
import type { JSONSchemaType } from 'ajv';
import type { PlaybookComponent } from '../playbook-types';
import type { StixBundle, StixObject } from '../../../types/stix-2-1-common';
import xtmOneClient from '../../xtm/one/xtm-one-client';
import { issueXtmJwt } from '../../../domain/xtm-auth';
import { getHttpClient, getResponseError } from '../../../utils/http-client';
import { logApp, PLATFORM_VERSION } from '../../../config/conf';
import { AUTOMATION_MANAGER_USER_UUID, executionContext } from '../../../utils/access';
import type { AuthContext, AuthUser } from '../../../types/user';

// ─── Configuration ─────────────────────────────────────────────────────────

interface AiAgentTransformConfiguration {
  agent_slug: string;
  prompt?: string;
}

const PLAYBOOK_AI_AGENT_TRANSFORM_INTENT = 'cti.stix_transformer';

// Identity used by the playbook executor when calling XTM One. The local
// part is stable so XTM One auto-provisions a single "OpenCTI Playbook
// Automation" user per deployment; the .invalid TLD (RFC 6761) makes it
// unmistakably non-human and impossible to collide with a real account.
const PLAYBOOK_AUTOMATION_EMAIL = 'opencti-playbook-automation@opencti.invalid';

const buildAutomationUser = (): Pick<AuthUser, 'id' | 'user_email'> => ({
  id: AUTOMATION_MANAGER_USER_UUID,
  user_email: PLAYBOOK_AUTOMATION_EMAIL,
});

// 5 minutes — agent runs may take a while when the LLM has to materialise
// a large STIX bundle. Keep well above the default 2-minute httpClient cap
// used by the chatbot proxy.
const AGENT_CALL_TIMEOUT_MS = 5 * 60 * 1000;

const PLAYBOOK_AI_AGENT_TRANSFORM_COMPONENT_SCHEMA: JSONSchemaType<AiAgentTransformConfiguration> = {
  type: 'object',
  properties: {
    agent_slug: {
      type: 'string',
      $ref: 'AI agent',
      // Populated dynamically from XTM One intent catalog at schema() time.
      oneOf: [],
    },
    prompt: {
      type: 'string',
      nullable: true,
      default: '',
      $ref: 'Additional instructions (optional, prepended to the STIX bundle)',
    },
  },
  required: ['agent_slug'],
};

// ─── Helpers ───────────────────────────────────────────────────────────────

/**
 * Extract a STIX bundle JSON object from an LLM response. Agents respond
 * either with a raw JSON object or with the bundle wrapped in a fenced
 * code block; both cases must be handled because we cannot rely on the
 * LLM never adding stray whitespace or markdown.
 */
const parseStixBundle = (raw: string): StixBundle | null => {
  const trimmed = raw.trim();
  if (!trimmed) return null;

  const fenceMatch = trimmed.match(/```(?:json)?\s*([\s\S]*?)```/i);
  const candidate = fenceMatch ? fenceMatch[1].trim() : trimmed;
  try {
    const parsed = JSON.parse(candidate);
    if (
      parsed
      && typeof parsed === 'object'
      && parsed.type === 'bundle'
      && Array.isArray(parsed.objects)
    ) {
      return parsed as StixBundle;
    }
  } catch {
    // Fall through and try a best-effort substring extraction.
  }

  const firstBrace = candidate.indexOf('{');
  const lastBrace = candidate.lastIndexOf('}');
  if (firstBrace !== -1 && lastBrace > firstBrace) {
    try {
      const parsed = JSON.parse(candidate.slice(firstBrace, lastBrace + 1));
      if (
        parsed
        && typeof parsed === 'object'
        && parsed.type === 'bundle'
        && Array.isArray(parsed.objects)
      ) {
        return parsed as StixBundle;
      }
    } catch {
      // Ignore — caller will fall back to the unmodified output port.
    }
  }
  return null;
};

const buildAgentPrompt = (bundle: StixBundle, userPrompt?: string): string => {
  const instruction = (userPrompt ?? '').trim();
  const bundleJson = JSON.stringify(bundle, null, 2);
  if (!instruction) {
    return `--- STIX BUNDLE ---\n${bundleJson}`;
  }
  return `${instruction}\n\n--- STIX BUNDLE ---\n${bundleJson}`;
};

/**
 * Synchronous, non-streaming call to XTM One Platform Chat. Returns the
 * raw assistant content or null when the call cannot complete (XTM One
 * not configured, network failure, non-success status). Errors are
 * logged but never thrown — playbook execution falls back to the
 * unmodified output port instead of crashing the whole run.
 */
const callAgent = async (
  agentSlug: string,
  content: string,
): Promise<string | null> => {
  const xtmOneUrl = nconf.get('xtm:xtm_one_url');
  if (!xtmOneUrl || !xtmOneClient.isConfigured()) {
    logApp.warn('[PLAYBOOK AI AGENT] XTM One is not configured, skipping agent call');
    return null;
  }

  try {
    const jwt = await issueXtmJwt(buildAutomationUser() as AuthUser, xtmOneUrl);
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

// ─── Component ─────────────────────────────────────────────────────────────

export const PLAYBOOK_AI_AGENT_TRANSFORM_COMPONENT: PlaybookComponent<AiAgentTransformConfiguration> = {
  id: 'PLAYBOOK_AI_AGENT_TRANSFORM_COMPONENT',
  name: 'Transform with AI agent',
  description: 'Send the STIX bundle to an AI agent and continue with the transformed bundle',
  icon: 'ai-agent',
  category: 'transform_and_enrich',
  is_entry_point: false,
  is_internal: true,
  ports: [{ id: 'out', type: 'out' }, { id: 'unmodified', type: 'out' }],
  configuration_schema: PLAYBOOK_AI_AGENT_TRANSFORM_COMPONENT_SCHEMA,
  schema: async () => {
    // Resolve the list of agents bound to the cti.stix_transformer intent
    // in XTM One so the playbook author can pick from a curated catalog
    // (built-in agents + user/group/company-managed agents the caller
    // is allowed to see). Falls back to an empty oneOf if XTM One is
    // unreachable so the form still renders cleanly.
    const context: AuthContext = executionContext('playbook_components');
    const automationContext: AuthContext = {
      ...context,
      user: buildAutomationUser() as AuthUser,
    };
    let agents: Awaited<ReturnType<typeof xtmOneClient.listAgentsForIntent>> = [];
    try {
      agents = await xtmOneClient.listAgentsForIntent(
        automationContext,
        PLAYBOOK_AI_AGENT_TRANSFORM_INTENT,
      );
    } catch (e: unknown) {
      logApp.warn('[PLAYBOOK AI AGENT] Failed to load agent catalog', { cause: (e as Error).message });
    }
    const elements = (agents ?? [])
      .filter((a) => !!a.agent_slug)
      .map((a) => ({ const: a.agent_slug as string, title: a.agent_name }))
      .sort((a, b) => (a.title.toLowerCase() > b.title.toLowerCase() ? 1 : -1));
    const schemaElement = { properties: { agent_slug: { oneOf: elements } } };
    return R.mergeDeepRight<JSONSchemaType<AiAgentTransformConfiguration>, any>(
      PLAYBOOK_AI_AGENT_TRANSFORM_COMPONENT_SCHEMA,
      schemaElement,
    );
  },
  executor: async ({ playbookNode, bundle }) => {
    const { agent_slug, prompt } = playbookNode.configuration;
    if (!agent_slug) {
      logApp.warn('[PLAYBOOK AI AGENT] No agent configured, returning bundle unmodified');
      return { output_port: 'unmodified', bundle };
    }
    const content = buildAgentPrompt(bundle, prompt);
    const rawResponse = await callAgent(agent_slug, content);
    if (rawResponse === null) {
      return { output_port: 'unmodified', bundle };
    }
    const transformedBundle = parseStixBundle(rawResponse);
    if (!transformedBundle) {
      logApp.warn('[PLAYBOOK AI AGENT] Could not parse agent response as a STIX bundle', {
        agentSlug: agent_slug,
        responsePreview: rawResponse.slice(0, 200),
      });
      return { output_port: 'unmodified', bundle };
    }
    // Preserve the original bundle envelope (id / spec_version) so
    // downstream nodes that key off them stay stable.  The agent is
    // free to materialise a fresh `objects` list — that is the whole
    // point of the transformation.
    const nextBundle: StixBundle = {
      ...bundle,
      objects: (transformedBundle.objects ?? []) as StixObject[],
    };
    return { output_port: 'out', bundle: nextBundle };
  },
};
