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
import { logApp } from '../../../config/conf';
import { buildAgentMessageContent, buildAgentSlugOneOf, callXtmAgent, isAgentBoundToIntent, resolveAgentJwtUser, resolveRunAsUserId } from './ai-agent-shared';

interface AiAgentSendConfiguration {
  agent_slug: string;
  // User the agent call runs as: the cross-platform JWT carries this
  // user's email so XTM One (and any write-back to OpenCTI) attributes the
  // work to a real account. Stored as the member-picker option.
  run_as?: { label: string; value: string };
  prompt?: string;
}

const PLAYBOOK_AI_AGENT_SEND_INTENT = 'cti.stix_consumer';

const PLAYBOOK_AI_AGENT_SEND_COMPONENT_SCHEMA: JSONSchemaType<AiAgentSendConfiguration> = {
  type: 'object',
  properties: {
    agent_slug: {
      type: 'string',
      $ref: 'AI agent',
      // Populated dynamically from the XTM One intent catalog at schema() time.
      oneOf: [],
    },
    run_as: {
      type: 'object',
      $ref: 'Run as',
      nullable: true,
      default: null,
      // Stored as the member-picker option ({ label, value }). The empty
      // oneOf keeps AJV's JSONSchemaType satisfied without enumerating the
      // option shape (same escape as the access-restrictions component).
      oneOf: [],
    },
    prompt: {
      type: 'string',
      nullable: true,
      default: '',
      $ref: 'Instructions (optional, prepended to the STIX bundle)',
      // `format: 'textarea'` is a UI hint consumed by the playbook form
      // renderer to display this field as a multi-line text area.
      format: 'textarea',
    },
  },
  required: ['agent_slug'],
};

/**
 * Fire-and-wait end-of-playbook component: sends the bundle and the
 * (optional) user instruction to an AI agent and waits for the call to
 * complete so that any side effects (Slack post, ticket creation,
 * outbound email, ...) the agent triggers via its own tools are flushed
 * before the playbook run is marked done.
 *
 * Unlike the transform component this is an **end node** (no output
 * port) — the agent's textual response is logged for traceability but
 * not parsed back into a STIX bundle. Use `Transform with AI agent` if
 * you need the response to drive the rest of the playbook chain.
 */
export const PLAYBOOK_AI_AGENT_SEND_COMPONENT: PlaybookComponent<AiAgentSendConfiguration> = {
  id: 'PLAYBOOK_AI_AGENT_SEND_COMPONENT',
  name: 'Send to AI agent',
  description: 'Send the STIX bundle to an AI agent as the final step of the playbook',
  icon: 'ai-agent',
  category: 'end_playbook',
  is_entry_point: false,
  is_internal: true,
  ports: [],
  configuration_schema: PLAYBOOK_AI_AGENT_SEND_COMPONENT_SCHEMA,
  schema: async () => {
    const elements = await buildAgentSlugOneOf(PLAYBOOK_AI_AGENT_SEND_INTENT);
    const schemaElement = { properties: { agent_slug: { oneOf: elements } } };
    return R.mergeDeepRight<JSONSchemaType<AiAgentSendConfiguration>, any>(
      PLAYBOOK_AI_AGENT_SEND_COMPONENT_SCHEMA,
      schemaElement,
    );
  },
  executor: async ({ playbookNode, bundle, playbookId }) => {
    const { agent_slug, prompt, run_as } = playbookNode.configuration;
    if (!agent_slug) {
      logApp.warn('[PLAYBOOK AI AGENT SEND] No agent configured, dropping playbook step', { playbookId });
      return { output_port: undefined, bundle, forceBundleTracking: true };
    }
    // Resolve the XTM One identity ONCE (run-as user, defaulting to the
    // seeded platform admin) and share it between the binding check and
    // the agent call: both are guaranteed to run as the same identity
    // with a single user lookup.
    const jwtUser = await resolveAgentJwtUser(resolveRunAsUserId(run_as));
    // Defense in depth: re-check that the configured slug is currently
    // bound to the consumer intent before invoking it. AJV `oneOf`
    // validation only covers saves that go through the schema resolver
    // — a crafted playbook update or an agent that was unbound after
    // save would otherwise let us run an arbitrary XTM One agent under
    // the configured run-as identity. The check runs as the SAME
    // identity as the agent call so the per-user XTM One catalog
    // visibility matches what the call will actually see.
    if (!(await isAgentBoundToIntent(PLAYBOOK_AI_AGENT_SEND_INTENT, agent_slug, jwtUser))) {
      logApp.warn('[PLAYBOOK AI AGENT SEND] Configured agent is not bound to the consumer intent, dropping playbook step', {
        playbookId,
        agentSlug: agent_slug,
        intent: PLAYBOOK_AI_AGENT_SEND_INTENT,
      });
      return { output_port: undefined, bundle, forceBundleTracking: true };
    }
    const content = buildAgentMessageContent(bundle, prompt);
    const rawResponse = await callXtmAgent(agent_slug, content, jwtUser);
    if (rawResponse === null) {
      logApp.warn('[PLAYBOOK AI AGENT SEND] Agent call did not complete', {
        playbookId,
        agentSlug: agent_slug,
      });
    } else {
      logApp.info('[PLAYBOOK AI AGENT SEND] Agent call completed', {
        playbookId,
        agentSlug: agent_slug,
        responsePreview: rawResponse.slice(0, 200),
      });
    }
    return { output_port: undefined, bundle, forceBundleTracking: true };
  },
};
