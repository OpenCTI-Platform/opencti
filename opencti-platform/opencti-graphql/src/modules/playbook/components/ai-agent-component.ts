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
import type { JSONSchemaType } from 'ajv';
import type { PlaybookComponent } from '../playbook-types';
import type { StixBundle, StixObject } from '../../../types/stix-2-1-common';
import { logApp } from '../../../config/conf';
import { buildAgentMessageContent, buildAgentSlugOneOf, callXtmAgent, isAgentBoundToIntent } from './ai-agent-shared';

// Canonical STIX 2.1 ID shape: `<type>--<uuid>` where the UUID is the
// 8-4-4-4-12 hex layout. Stricter than the loose `[\w-]{36}` pattern in
// `src/schema/schemaUtils.js` (which accepts underscores) so that we
// reject malformed agent output instead of forwarding it as a "bundle".
// Inlined here as a regex constant to keep the component unit-testable
// without dragging the schema module's transitive closure into the
// test runner.
const STIX_UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

interface AiAgentTransformConfiguration {
  agent_slug: string;
  prompt?: string;
}

const PLAYBOOK_AI_AGENT_TRANSFORM_INTENT = 'cti.stix_transformer';

const PLAYBOOK_AI_AGENT_TRANSFORM_COMPONENT_SCHEMA: JSONSchemaType<AiAgentTransformConfiguration> = {
  type: 'object',
  properties: {
    agent_slug: {
      type: 'string',
      $ref: 'AI agent',
      // Populated dynamically from the XTM One intent catalog at schema() time.
      oneOf: [],
    },
    prompt: {
      type: 'string',
      nullable: true,
      default: '',
      $ref: 'Additional instructions (optional, prepended to the STIX bundle)',
      // `format: 'textarea'` is a UI hint consumed by the playbook form
      // renderer to display this field as a multi-line text area. AJV
      // does not enforce the format keyword so this is purely cosmetic.
      format: 'textarea',
    },
  },
  required: ['agent_slug'],
};

/**
 * Minimum STIX 2.1 object shape we accept from the agent: a non-empty
 * `type` string AND an `id` of the canonical `<type>--<uuid>` shape
 * where the prefix before `--` matches the object's own `type` field
 * exactly and the suffix is a strict 8-4-4-4-12 hex UUID. Anything
 * looser (mismatched type prefix, underscores in the UUID, missing
 * separator, ...) is silently corrupted by the agent and should not be
 * forwarded to the downstream playbook nodes.
 */
const isMinimalStixObjectShape = (candidate: unknown): boolean => {
  if (!candidate || typeof candidate !== 'object') return false;
  const obj = candidate as { id?: unknown; type?: unknown };
  if (typeof obj.type !== 'string' || obj.type.length === 0) return false;
  if (typeof obj.id !== 'string') return false;
  const separatorIndex = obj.id.indexOf('--');
  if (separatorIndex <= 0) return false;
  const idTypePrefix = obj.id.slice(0, separatorIndex);
  const idUuid = obj.id.slice(separatorIndex + 2);
  return idTypePrefix === obj.type && STIX_UUID_REGEX.test(idUuid);
};

/**
 * Returns the candidate as a STIX bundle when it has the expected
 * envelope (`type: 'bundle'`, `objects` is an array) AND every object
 * in the array passes the minimum STIX shape check. An empty
 * `objects: []` is treated as valid — the agent legitimately filtered
 * everything out — but a single malformed object rejects the whole
 * bundle so we never forward partially-corrupt data to downstream
 * nodes.
 */
const asValidStixBundle = (candidate: unknown): StixBundle | null => {
  if (
    candidate
    && typeof candidate === 'object'
    && (candidate as { type?: unknown }).type === 'bundle'
    && Array.isArray((candidate as { objects?: unknown }).objects)
    && (candidate as { objects: unknown[] }).objects.every(isMinimalStixObjectShape)
  ) {
    return candidate as StixBundle;
  }
  return null;
};

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
    const validated = asValidStixBundle(JSON.parse(candidate));
    if (validated) return validated;
  } catch {
    // Fall through and try a best-effort substring extraction.
  }

  const firstBrace = candidate.indexOf('{');
  const lastBrace = candidate.lastIndexOf('}');
  if (firstBrace !== -1 && lastBrace > firstBrace) {
    try {
      const validated = asValidStixBundle(JSON.parse(candidate.slice(firstBrace, lastBrace + 1)));
      if (validated) return validated;
    } catch {
      // Ignore — caller will fall back to the unmodified output port.
    }
  }
  return null;
};

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
    const elements = await buildAgentSlugOneOf(PLAYBOOK_AI_AGENT_TRANSFORM_INTENT);
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
    // Defense in depth: re-check that the configured slug is currently
    // bound to the transformer intent. AJV `oneOf` validation only
    // covers saves that go through the schema resolver — a crafted
    // playbook update or an agent that was unbound after save would
    // otherwise let us run an arbitrary XTM One agent under the
    // platform automation identity.
    if (!(await isAgentBoundToIntent(PLAYBOOK_AI_AGENT_TRANSFORM_INTENT, agent_slug))) {
      logApp.warn('[PLAYBOOK AI AGENT] Configured agent is not bound to the transformer intent, returning bundle unmodified', {
        agentSlug: agent_slug,
        intent: PLAYBOOK_AI_AGENT_TRANSFORM_INTENT,
      });
      return { output_port: 'unmodified', bundle };
    }
    const content = buildAgentMessageContent(bundle, prompt);
    const rawResponse = await callXtmAgent(agent_slug, content);
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
