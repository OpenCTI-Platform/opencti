import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

// ── Mocks (declared before the SUT import) ──────────────────────────────

vi.mock('../../../../../src/modules/playbook/components/ai-agent-shared', () => ({
  buildAgentMessageContent: vi.fn(),
  buildAgentSlugOneOf: vi.fn(),
  callXtmAgent: vi.fn(),
  isAgentBoundToIntent: vi.fn(),
  isXtmOneConfigured: vi.fn(),
  resolveAgentJwtUser: vi.fn(),
  resolveRunAsUserId: vi.fn(),
}));

vi.mock('../../../../../src/config/conf', () => ({
  logApp: { info: vi.fn(), warn: vi.fn(), error: vi.fn() },
}));

// ── Imports (after mocks) ───────────────────────────────────────────────

import { PLAYBOOK_AI_AGENT_SEND_COMPONENT } from '../../../../../src/modules/playbook/components/ai-agent-send-component';
import {
  buildAgentMessageContent,
  buildAgentSlugOneOf,
  callXtmAgent,
  isAgentBoundToIntent,
  isXtmOneConfigured,
  resolveAgentJwtUser,
  resolveRunAsUserId,
} from '../../../../../src/modules/playbook/components/ai-agent-shared';
import type { StixBundle } from '../../../../../src/types/stix-2-1-common';
import type { ExecutorParameters } from '../../../../../src/modules/playbook/playbook-types';

// ── Fixtures ────────────────────────────────────────────────────────────

const BUNDLE: StixBundle = {
  id: 'bundle--original',
  spec_version: '2.1',
  type: 'bundle',
  objects: [],
};

// Identity resolved once by the executor and shared between the binding
// check and the agent call.
const JWT_USER = { id: 'jwt-user-id', user_email: 'jwt-user@org.test' };

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
    // XTM One configured by default; the unconfigured test overrides this.
    vi.mocked(isXtmOneConfigured).mockReturnValue(true);
    // No run-as user configured by default; tests that need it override this.
    vi.mocked(resolveRunAsUserId).mockReturnValue(undefined);
    // The executor resolves the JWT identity once and forwards it to both
    // the binding check and the agent call.
    vi.mocked(resolveAgentJwtUser).mockResolvedValue(JWT_USER);
    // Default to "agent slug is bound to the consumer intent" so the
    // existing tests exercise the live path; tests that need the
    // negative branch override this explicitly.
    vi.mocked(isAgentBoundToIntent).mockResolvedValue(true);
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

    it('should drop the step without any user lookup or XTM One call when XTM One is not configured', async () => {
      vi.mocked(isXtmOneConfigured).mockReturnValue(false);

      const result = await PLAYBOOK_AI_AGENT_SEND_COMPONENT.executor(
        buildExecutorParams({ agent_slug: 'agent-x' }),
      );

      expect(resolveAgentJwtUser).not.toHaveBeenCalled();
      expect(isAgentBoundToIntent).not.toHaveBeenCalled();
      expect(callXtmAgent).not.toHaveBeenCalled();
      expect(result.output_port).toBeUndefined();
      expect(result.bundle).toBe(BUNDLE);
      expect(result.forceBundleTracking).toBe(true);
    });

    it('should drop the step (no binding check, no agent call) when no JWT identity can be resolved', async () => {
      vi.mocked(resolveAgentJwtUser).mockResolvedValue(null);

      const result = await PLAYBOOK_AI_AGENT_SEND_COMPONENT.executor(
        buildExecutorParams({ agent_slug: 'agent-x' }),
      );

      expect(isAgentBoundToIntent).not.toHaveBeenCalled();
      expect(callXtmAgent).not.toHaveBeenCalled();
      expect(result.output_port).toBeUndefined();
      expect(result.bundle).toBe(BUNDLE);
      expect(result.forceBundleTracking).toBe(true);
    });

    it('should drop the step (no agent call) when the slug is not bound to the cti.stix_consumer intent (defense in depth)', async () => {
      vi.mocked(isAgentBoundToIntent).mockResolvedValue(false);

      const result = await PLAYBOOK_AI_AGENT_SEND_COMPONENT.executor(
        buildExecutorParams({ agent_slug: 'agent-not-bound-to-consumer' }),
      );

      expect(isAgentBoundToIntent).toHaveBeenCalledWith('cti.stix_consumer', 'agent-not-bound-to-consumer', JWT_USER);
      expect(callXtmAgent).not.toHaveBeenCalled();
      expect(result.output_port).toBeUndefined();
      expect(result.bundle).toBe(BUNDLE);
      expect(result.forceBundleTracking).toBe(true);
    });

    it('should validate the slug against cti.stix_consumer before each agent call', async () => {
      vi.mocked(callXtmAgent).mockResolvedValue('reply');

      await PLAYBOOK_AI_AGENT_SEND_COMPONENT.executor(
        buildExecutorParams({ agent_slug: 'agent-x' }),
      );

      expect(isAgentBoundToIntent).toHaveBeenCalledWith('cti.stix_consumer', 'agent-x', JWT_USER);
    });

    it('should call the agent and still terminate cleanly (bundle tracked) when the agent responds', async () => {
      vi.mocked(callXtmAgent).mockResolvedValue('agent reply');

      const result = await PLAYBOOK_AI_AGENT_SEND_COMPONENT.executor(
        buildExecutorParams({ agent_slug: 'agent-x', prompt: 'do something' }),
      );

      expect(buildAgentMessageContent).toHaveBeenCalledWith(BUNDLE, 'do something');
      expect(callXtmAgent).toHaveBeenCalledWith('agent-x', 'built content', JWT_USER);
      expect(result.output_port).toBeUndefined();
      expect(result.bundle).toBe(BUNDLE);
      expect(result.forceBundleTracking).toBe(true);
    });

    it('should terminate cleanly (bundle tracked) even when the agent call fails (callXtmAgent returns null)', async () => {
      vi.mocked(callXtmAgent).mockResolvedValue(null);

      const result = await PLAYBOOK_AI_AGENT_SEND_COMPONENT.executor(
        buildExecutorParams({ agent_slug: 'agent-x' }),
      );

      expect(callXtmAgent).toHaveBeenCalledWith('agent-x', 'built content', JWT_USER);
      expect(result.output_port).toBeUndefined();
      expect(result.bundle).toBe(BUNDLE);
      expect(result.forceBundleTracking).toBe(true);
    });

    it('should resolve the JWT identity ONCE from the configured run-as user and forward it to both the binding check and the agent call', async () => {
      vi.mocked(resolveRunAsUserId).mockReturnValue('run-as-user-id');
      vi.mocked(callXtmAgent).mockResolvedValue('reply');

      await PLAYBOOK_AI_AGENT_SEND_COMPONENT.executor(
        buildExecutorParams({ agent_slug: 'agent-x' }),
      );

      expect(resolveAgentJwtUser).toHaveBeenCalledTimes(1);
      expect(resolveAgentJwtUser).toHaveBeenCalledWith('run-as-user-id');
      expect(isAgentBoundToIntent).toHaveBeenCalledWith('cti.stix_consumer', 'agent-x', JWT_USER);
      expect(callXtmAgent).toHaveBeenCalledWith('agent-x', 'built content', JWT_USER);
    });
  });
});
