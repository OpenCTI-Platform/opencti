import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

// ── Mocks (declared before the SUT import) ──────────────────────────────

vi.mock('../../../../../src/modules/playbook/components/ai-agent-shared', () => ({
  buildAgentMessageContent: vi.fn(),
  buildAgentSlugOneOf: vi.fn(),
  callXtmAgent: vi.fn(),
}));

vi.mock('../../../../../src/config/conf', () => ({
  logApp: { info: vi.fn(), warn: vi.fn(), error: vi.fn() },
}));

// ── Imports (after mocks) ───────────────────────────────────────────────

import { PLAYBOOK_AI_AGENT_SEND_COMPONENT } from '../../../../../src/modules/playbook/components/ai-agent-send-component';
import { buildAgentMessageContent, buildAgentSlugOneOf, callXtmAgent } from '../../../../../src/modules/playbook/components/ai-agent-shared';
import type { StixBundle } from '../../../../../src/types/stix-2-1-common';
import type { ExecutorParameters } from '../../../../../src/modules/playbook/playbook-types';

// ── Fixtures ────────────────────────────────────────────────────────────

const BUNDLE: StixBundle = {
  id: 'bundle--original',
  spec_version: '2.1',
  type: 'bundle',
  objects: [],
};

const buildExecutorParams = (configuration: { agent_slug: string; prompt?: string }) => ({
  eventId: 'event-id',
  executionId: 'execution-id',
  playbookId: 'playbook-id',
  dataInstanceId: 'data-instance-id',
  previousPlaybookNodeId: undefined,
  previousStepBundle: null,
  bundle: BUNDLE,
  playbookNode: {
    id: 'node-id',
    name: 'Send Node',
    component_id: PLAYBOOK_AI_AGENT_SEND_COMPONENT.id,
    configuration,
  },
}) as unknown as ExecutorParameters<{ agent_slug: string; prompt?: string }>;

// ── Tests ───────────────────────────────────────────────────────────────

describe('PLAYBOOK_AI_AGENT_SEND_COMPONENT', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(buildAgentMessageContent).mockReturnValue('built content');
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('component metadata', () => {
    it('should be an end-playbook component with no output ports', () => {
      expect(PLAYBOOK_AI_AGENT_SEND_COMPONENT.category).toBe('end_playbook');
      expect(PLAYBOOK_AI_AGENT_SEND_COMPONENT.ports).toEqual([]);
      expect(PLAYBOOK_AI_AGENT_SEND_COMPONENT.is_internal).toBe(true);
      expect(PLAYBOOK_AI_AGENT_SEND_COMPONENT.icon).toBe('ai-agent');
    });
  });

  describe('schema()', () => {
    it('should hydrate the agent_slug oneOf from the XTM One catalog for the cti.stix_consumer intent', async () => {
      vi.mocked(buildAgentSlugOneOf).mockResolvedValue([
        { const: 'agent-a', title: 'Agent A' },
      ]);

      const schema = await PLAYBOOK_AI_AGENT_SEND_COMPONENT.schema();

      expect(buildAgentSlugOneOf).toHaveBeenCalledWith('cti.stix_consumer');
      expect((schema as any).properties.agent_slug.oneOf).toEqual([
        { const: 'agent-a', title: 'Agent A' },
      ]);
    });
  });

  describe('executor', () => {
    it('should drop the step (no agent call) and force bundle tracking when no agent is configured', async () => {
      const result = await PLAYBOOK_AI_AGENT_SEND_COMPONENT.executor(
        buildExecutorParams({ agent_slug: '' }),
      );

      expect(callXtmAgent).not.toHaveBeenCalled();
      expect(result.output_port).toBeUndefined();
      expect(result.bundle).toBe(BUNDLE);
      expect(result.forceBundleTracking).toBe(true);
    });

    it('should call the agent and still terminate cleanly (bundle tracked) when the agent responds', async () => {
      vi.mocked(callXtmAgent).mockResolvedValue('agent reply');

      const result = await PLAYBOOK_AI_AGENT_SEND_COMPONENT.executor(
        buildExecutorParams({ agent_slug: 'agent-x', prompt: 'do something' }),
      );

      expect(buildAgentMessageContent).toHaveBeenCalledWith(BUNDLE, 'do something');
      expect(callXtmAgent).toHaveBeenCalledWith('agent-x', 'built content');
      expect(result.output_port).toBeUndefined();
      expect(result.bundle).toBe(BUNDLE);
      expect(result.forceBundleTracking).toBe(true);
    });

    it('should terminate cleanly (bundle tracked) even when the agent call fails (callXtmAgent returns null)', async () => {
      vi.mocked(callXtmAgent).mockResolvedValue(null);

      const result = await PLAYBOOK_AI_AGENT_SEND_COMPONENT.executor(
        buildExecutorParams({ agent_slug: 'agent-x' }),
      );

      expect(callXtmAgent).toHaveBeenCalledWith('agent-x', 'built content');
      expect(result.output_port).toBeUndefined();
      expect(result.bundle).toBe(BUNDLE);
      expect(result.forceBundleTracking).toBe(true);
    });
  });
});
