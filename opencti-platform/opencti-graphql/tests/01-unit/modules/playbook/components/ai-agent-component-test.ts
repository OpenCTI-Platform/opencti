import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

// ── Mocks (declared before the SUT import) ──────────────────────────────

vi.mock('../../../../../src/modules/playbook/components/ai-agent-shared', () => ({
  buildAgentMessageContent: vi.fn(),
  buildAgentSlugOneOf: vi.fn(),
  callXtmAgent: vi.fn(),
  isAgentBoundToIntent: vi.fn(),
}));

vi.mock('../../../../../src/config/conf', () => ({
  logApp: { info: vi.fn(), warn: vi.fn(), error: vi.fn() },
}));

// ── Imports (after mocks) ───────────────────────────────────────────────

import { PLAYBOOK_AI_AGENT_TRANSFORM_COMPONENT } from '../../../../../src/modules/playbook/components/ai-agent-component';
import { buildAgentMessageContent, buildAgentSlugOneOf, callXtmAgent, isAgentBoundToIntent } from '../../../../../src/modules/playbook/components/ai-agent-shared';
import type { StixBundle } from '../../../../../src/types/stix-2-1-common';
import type { ExecutorParameters } from '../../../../../src/modules/playbook/playbook-types';

// ── Fixtures ────────────────────────────────────────────────────────────

// Use full <type>--<uuid> STIX IDs (matching `[a-z-]+--[\w-]{36}`) so the
// minimum-shape validator inside the parser accepts them — STIX 2.1
// rejects anything looser.
const ORIGINAL_INDICATOR_ID = 'indicator--11111111-1111-1111-1111-111111111111';
const TRANSFORMED_INDICATOR_ID = 'indicator--22222222-2222-2222-2222-222222222222';

const ORIGINAL_BUNDLE: StixBundle = {
  id: 'bundle--original',
  spec_version: '2.1',
  type: 'bundle',
  objects: [
    { id: ORIGINAL_INDICATOR_ID, type: 'indicator', spec_version: '2.1' } as any,
  ],
};

const TRANSFORMED_BUNDLE_OBJECT = { id: TRANSFORMED_INDICATOR_ID, type: 'indicator', spec_version: '2.1' };

const buildExecutorParams = (
  configuration: { agent_slug: string; prompt?: string },
  bundle: StixBundle = ORIGINAL_BUNDLE,
) => ({
  eventId: 'event-id',
  executionId: 'execution-id',
  playbookId: 'playbook-id',
  dataInstanceId: 'data-instance-id',
  previousPlaybookNodeId: undefined,
  previousStepBundle: null,
  bundle,
  playbookNode: {
    id: 'node-id',
    name: 'Transform Node',
    component_id: PLAYBOOK_AI_AGENT_TRANSFORM_COMPONENT.id,
    configuration,
  },
}) as unknown as ExecutorParameters<{ agent_slug: string; prompt?: string }>;

// ── Tests ───────────────────────────────────────────────────────────────

describe('PLAYBOOK_AI_AGENT_TRANSFORM_COMPONENT', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(buildAgentMessageContent).mockReturnValue('built content');
    // Default to "agent slug is bound to the right intent" so existing
    // tests exercise the live agent-call path; tests that need the
    // negative branch override this explicitly.
    vi.mocked(isAgentBoundToIntent).mockResolvedValue(true);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('component metadata', () => {
    it('should be flagged is_internal and use the ai-agent icon', () => {
      expect(PLAYBOOK_AI_AGENT_TRANSFORM_COMPONENT.is_internal).toBe(true);
      expect(PLAYBOOK_AI_AGENT_TRANSFORM_COMPONENT.icon).toBe('ai-agent');
      expect(PLAYBOOK_AI_AGENT_TRANSFORM_COMPONENT.category).toBe('transform_and_enrich');
    });

    it('should expose `out` and `unmodified` output ports so playbook authors can branch on agent failure', () => {
      const portIds = PLAYBOOK_AI_AGENT_TRANSFORM_COMPONENT.ports.map((p) => p.id).sort();
      expect(portIds).toEqual(['out', 'unmodified']);
    });
  });

  describe('schema()', () => {
    it('should hydrate the agent_slug oneOf from the XTM One catalog for the cti.stix_transformer intent', async () => {
      vi.mocked(buildAgentSlugOneOf).mockResolvedValue([
        { const: 'agent-a', title: 'Agent A' },
      ]);

      const schema = await PLAYBOOK_AI_AGENT_TRANSFORM_COMPONENT.schema();

      expect(buildAgentSlugOneOf).toHaveBeenCalledWith('cti.stix_transformer');
      expect((schema as any).properties.agent_slug.oneOf).toEqual([
        { const: 'agent-a', title: 'Agent A' },
      ]);
    });

    it('should still produce a valid schema (empty oneOf) when no agents are bound to the intent', async () => {
      vi.mocked(buildAgentSlugOneOf).mockResolvedValue([]);

      const schema = await PLAYBOOK_AI_AGENT_TRANSFORM_COMPONENT.schema();

      expect((schema as any).properties.agent_slug.oneOf).toEqual([]);
    });
  });

  describe('executor', () => {
    it('should route to `unmodified` and not call XTM One when no agent_slug is configured', async () => {
      const result = await PLAYBOOK_AI_AGENT_TRANSFORM_COMPONENT.executor(
        buildExecutorParams({ agent_slug: '' }),
      );

      expect(callXtmAgent).not.toHaveBeenCalled();
      expect(result.output_port).toBe('unmodified');
      expect(result.bundle).toBe(ORIGINAL_BUNDLE);
    });

    it('should route to `unmodified` and not call XTM One when the slug is not bound to the cti.stix_transformer intent (defense in depth)', async () => {
      vi.mocked(isAgentBoundToIntent).mockResolvedValue(false);

      const result = await PLAYBOOK_AI_AGENT_TRANSFORM_COMPONENT.executor(
        buildExecutorParams({ agent_slug: 'agent-not-bound-to-transformer' }),
      );

      expect(isAgentBoundToIntent).toHaveBeenCalledWith('cti.stix_transformer', 'agent-not-bound-to-transformer');
      expect(callXtmAgent).not.toHaveBeenCalled();
      expect(result.output_port).toBe('unmodified');
      expect(result.bundle).toBe(ORIGINAL_BUNDLE);
    });

    it('should validate the slug against cti.stix_transformer before each agent call', async () => {
      vi.mocked(callXtmAgent).mockResolvedValue(null);

      await PLAYBOOK_AI_AGENT_TRANSFORM_COMPONENT.executor(
        buildExecutorParams({ agent_slug: 'agent-x' }),
      );

      expect(isAgentBoundToIntent).toHaveBeenCalledWith('cti.stix_transformer', 'agent-x');
    });

    it('should route to `unmodified` when XTM One call fails (callXtmAgent returns null)', async () => {
      vi.mocked(callXtmAgent).mockResolvedValue(null);

      const result = await PLAYBOOK_AI_AGENT_TRANSFORM_COMPONENT.executor(
        buildExecutorParams({ agent_slug: 'agent-x' }),
      );

      expect(callXtmAgent).toHaveBeenCalledWith('agent-x', 'built content');
      expect(result.output_port).toBe('unmodified');
      expect(result.bundle).toBe(ORIGINAL_BUNDLE);
    });

    it('should accept a raw JSON STIX bundle response and emit a new bundle preserving the original envelope', async () => {
      const agentResponse = JSON.stringify({
        id: 'bundle--agent',
        spec_version: '2.1',
        type: 'bundle',
        objects: [TRANSFORMED_BUNDLE_OBJECT],
      });
      vi.mocked(callXtmAgent).mockResolvedValue(agentResponse);

      const result = await PLAYBOOK_AI_AGENT_TRANSFORM_COMPONENT.executor(
        buildExecutorParams({ agent_slug: 'agent-x' }),
      );

      expect(result.output_port).toBe('out');
      // Envelope is preserved (id + spec_version stay from the original bundle).
      expect(result.bundle.id).toBe(ORIGINAL_BUNDLE.id);
      expect(result.bundle.spec_version).toBe(ORIGINAL_BUNDLE.spec_version);
      // But the objects come from the agent response.
      expect(result.bundle.objects).toEqual([TRANSFORMED_BUNDLE_OBJECT]);
    });

    it('should extract the bundle from a fenced ```json block', async () => {
      const agentResponse = [
        'Here is the bundle:',
        '```json',
        JSON.stringify({ id: 'bundle--agent', spec_version: '2.1', type: 'bundle', objects: [TRANSFORMED_BUNDLE_OBJECT] }),
        '```',
        'Hope this helps!',
      ].join('\n');
      vi.mocked(callXtmAgent).mockResolvedValue(agentResponse);

      const result = await PLAYBOOK_AI_AGENT_TRANSFORM_COMPONENT.executor(
        buildExecutorParams({ agent_slug: 'agent-x' }),
      );

      expect(result.output_port).toBe('out');
      expect(result.bundle.objects).toEqual([TRANSFORMED_BUNDLE_OBJECT]);
    });

    it('should extract the bundle from a plain ``` fenced block (no language hint)', async () => {
      const agentResponse = [
        '```',
        JSON.stringify({ id: 'bundle--agent', spec_version: '2.1', type: 'bundle', objects: [TRANSFORMED_BUNDLE_OBJECT] }),
        '```',
      ].join('\n');
      vi.mocked(callXtmAgent).mockResolvedValue(agentResponse);

      const result = await PLAYBOOK_AI_AGENT_TRANSFORM_COMPONENT.executor(
        buildExecutorParams({ agent_slug: 'agent-x' }),
      );

      expect(result.output_port).toBe('out');
      expect(result.bundle.objects).toEqual([TRANSFORMED_BUNDLE_OBJECT]);
    });

    it('should fall back to best-effort `{...}` substring extraction when the response has prose around the JSON', async () => {
      const bundleJson = JSON.stringify({
        id: 'bundle--agent',
        spec_version: '2.1',
        type: 'bundle',
        objects: [TRANSFORMED_BUNDLE_OBJECT],
      });
      const agentResponse = `Sure, here you go: ${bundleJson} let me know if you need anything else.`;
      vi.mocked(callXtmAgent).mockResolvedValue(agentResponse);

      const result = await PLAYBOOK_AI_AGENT_TRANSFORM_COMPONENT.executor(
        buildExecutorParams({ agent_slug: 'agent-x' }),
      );

      expect(result.output_port).toBe('out');
      expect(result.bundle.objects).toEqual([TRANSFORMED_BUNDLE_OBJECT]);
    });

    it('should route to `unmodified` when the response is empty', async () => {
      vi.mocked(callXtmAgent).mockResolvedValue('   ');

      const result = await PLAYBOOK_AI_AGENT_TRANSFORM_COMPONENT.executor(
        buildExecutorParams({ agent_slug: 'agent-x' }),
      );

      expect(result.output_port).toBe('unmodified');
      expect(result.bundle).toBe(ORIGINAL_BUNDLE);
    });

    it('should route to `unmodified` when the parsed JSON is not a STIX bundle (wrong type)', async () => {
      vi.mocked(callXtmAgent).mockResolvedValue(JSON.stringify({ type: 'not-a-bundle', objects: [] }));

      const result = await PLAYBOOK_AI_AGENT_TRANSFORM_COMPONENT.executor(
        buildExecutorParams({ agent_slug: 'agent-x' }),
      );

      expect(result.output_port).toBe('unmodified');
      expect(result.bundle).toBe(ORIGINAL_BUNDLE);
    });

    it('should route to `unmodified` when the parsed bundle has no objects array', async () => {
      vi.mocked(callXtmAgent).mockResolvedValue(JSON.stringify({ type: 'bundle' }));

      const result = await PLAYBOOK_AI_AGENT_TRANSFORM_COMPONENT.executor(
        buildExecutorParams({ agent_slug: 'agent-x' }),
      );

      expect(result.output_port).toBe('unmodified');
      expect(result.bundle).toBe(ORIGINAL_BUNDLE);
    });

    it('should route to `unmodified` when the response is unparseable prose', async () => {
      vi.mocked(callXtmAgent).mockResolvedValue('Sorry, I cannot help with this request.');

      const result = await PLAYBOOK_AI_AGENT_TRANSFORM_COMPONENT.executor(
        buildExecutorParams({ agent_slug: 'agent-x' }),
      );

      expect(result.output_port).toBe('unmodified');
      expect(result.bundle).toBe(ORIGINAL_BUNDLE);
    });

    it('should route to `unmodified` when an object in the bundle is an empty `{}` placeholder', async () => {
      vi.mocked(callXtmAgent).mockResolvedValue(JSON.stringify({
        type: 'bundle',
        id: 'bundle--agent',
        spec_version: '2.1',
        objects: [{}],
      }));

      const result = await PLAYBOOK_AI_AGENT_TRANSFORM_COMPONENT.executor(
        buildExecutorParams({ agent_slug: 'agent-x' }),
      );

      expect(result.output_port).toBe('unmodified');
      expect(result.bundle).toBe(ORIGINAL_BUNDLE);
    });

    it('should route to `unmodified` when an object is missing the STIX id', async () => {
      vi.mocked(callXtmAgent).mockResolvedValue(JSON.stringify({
        type: 'bundle',
        id: 'bundle--agent',
        spec_version: '2.1',
        objects: [{ type: 'indicator', spec_version: '2.1' }],
      }));

      const result = await PLAYBOOK_AI_AGENT_TRANSFORM_COMPONENT.executor(
        buildExecutorParams({ agent_slug: 'agent-x' }),
      );

      expect(result.output_port).toBe('unmodified');
      expect(result.bundle).toBe(ORIGINAL_BUNDLE);
    });

    it('should route to `unmodified` when an object has an id that does not match the STIX <type>--<uuid> pattern', async () => {
      vi.mocked(callXtmAgent).mockResolvedValue(JSON.stringify({
        type: 'bundle',
        id: 'bundle--agent',
        spec_version: '2.1',
        objects: [{ id: 'indicator-42', type: 'indicator', spec_version: '2.1' }],
      }));

      const result = await PLAYBOOK_AI_AGENT_TRANSFORM_COMPONENT.executor(
        buildExecutorParams({ agent_slug: 'agent-x' }),
      );

      expect(result.output_port).toBe('unmodified');
      expect(result.bundle).toBe(ORIGINAL_BUNDLE);
    });

    it('should route to `unmodified` when the id type prefix does not match the object type field', async () => {
      vi.mocked(callXtmAgent).mockResolvedValue(JSON.stringify({
        type: 'bundle',
        id: 'bundle--agent',
        spec_version: '2.1',
        objects: [{
          id: 'malware--33333333-3333-3333-3333-333333333333',
          type: 'indicator',
          spec_version: '2.1',
        }],
      }));

      const result = await PLAYBOOK_AI_AGENT_TRANSFORM_COMPONENT.executor(
        buildExecutorParams({ agent_slug: 'agent-x' }),
      );

      expect(result.output_port).toBe('unmodified');
      expect(result.bundle).toBe(ORIGINAL_BUNDLE);
    });

    it('should route to `unmodified` when the UUID segment is not a valid 8-4-4-4-12 hex (e.g. underscores, wrong length)', async () => {
      const invalidUuids = [
        'indicator--12345678_1234_1234_1234_123456789012', // underscores instead of hyphens
        'indicator--zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz', // non-hex characters
        'indicator--1234-1234-1234-1234-1234567890ab', // wrong segment lengths
      ];
      for (const id of invalidUuids) {
        vi.mocked(callXtmAgent).mockResolvedValue(JSON.stringify({
          type: 'bundle',
          id: 'bundle--agent',
          spec_version: '2.1',
          objects: [{ id, type: 'indicator', spec_version: '2.1' }],
        }));

        const result = await PLAYBOOK_AI_AGENT_TRANSFORM_COMPONENT.executor(
          buildExecutorParams({ agent_slug: 'agent-x' }),
        );

        expect(result.output_port, `id ${id} should be rejected`).toBe('unmodified');
        expect(result.bundle).toBe(ORIGINAL_BUNDLE);
      }
    });

    it('should route to `unmodified` when any one object in a mixed-validity bundle is malformed (whole bundle rejected)', async () => {
      vi.mocked(callXtmAgent).mockResolvedValue(JSON.stringify({
        type: 'bundle',
        id: 'bundle--agent',
        spec_version: '2.1',
        objects: [TRANSFORMED_BUNDLE_OBJECT, { id: 'bad-id' }],
      }));

      const result = await PLAYBOOK_AI_AGENT_TRANSFORM_COMPONENT.executor(
        buildExecutorParams({ agent_slug: 'agent-x' }),
      );

      expect(result.output_port).toBe('unmodified');
      expect(result.bundle).toBe(ORIGINAL_BUNDLE);
    });

    it('should accept an empty `objects: []` bundle (agent legitimately filtered everything out)', async () => {
      vi.mocked(callXtmAgent).mockResolvedValue(JSON.stringify({
        type: 'bundle',
        id: 'bundle--agent',
        spec_version: '2.1',
        objects: [],
      }));

      const result = await PLAYBOOK_AI_AGENT_TRANSFORM_COMPONENT.executor(
        buildExecutorParams({ agent_slug: 'agent-x' }),
      );

      expect(result.output_port).toBe('out');
      expect(result.bundle.objects).toEqual([]);
    });

    it('should forward the bundle and the user prompt to the message builder', async () => {
      vi.mocked(callXtmAgent).mockResolvedValue(null);

      await PLAYBOOK_AI_AGENT_TRANSFORM_COMPONENT.executor(
        buildExecutorParams({ agent_slug: 'agent-x', prompt: 'Tag everything' }),
      );

      expect(buildAgentMessageContent).toHaveBeenCalledWith(ORIGINAL_BUNDLE, 'Tag everything');
    });
  });
});
