import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

// ── Mocks (must be declared before the SUT import below) ────────────────

vi.mock('nconf', () => ({
  default: { get: vi.fn() },
}));

vi.mock('../../../../../src/modules/xtm/one/xtm-one-client', () => ({
  default: {
    isConfigured: vi.fn(),
    listAgentsForIntent: vi.fn(),
  },
}));

vi.mock('../../../../../src/domain/xtm-auth', () => ({
  issueXtmJwt: vi.fn(),
}));

vi.mock('../../../../../src/utils/http-client', () => ({
  getHttpClient: vi.fn(),
  getResponseError: vi.fn((e: any) => (e && typeof e === 'object' && 'response' in e ? e.response : null)),
}));

vi.mock('../../../../../src/config/conf', () => ({
  logApp: { info: vi.fn(), warn: vi.fn(), error: vi.fn() },
  PLATFORM_VERSION: '6.0.0-test',
}));

vi.mock('../../../../../src/utils/access', () => ({
  AUTOMATION_MANAGER_USER: { id: 'automation-manager', user_email: 'AUTOMATION MANAGER' },
  SYSTEM_USER: { id: 'system', user_email: 'SYSTEM' },
  executionContext: vi.fn((source: string) => ({ source })),
}));

vi.mock('../../../../../src/database/middleware-loader', () => ({
  internalLoadById: vi.fn(),
}));

vi.mock('../../../../../src/schema/internalObject', () => ({
  ENTITY_TYPE_USER: 'User',
}));

vi.mock('../../../../../src/schema/general', () => ({
  OPENCTI_ADMIN_UUID: 'admin-uuid',
}));

// ── Imports (after mocks) ───────────────────────────────────────────────

import nconf from 'nconf';
import xtmOneClient from '../../../../../src/modules/xtm/one/xtm-one-client';
import { issueXtmJwt } from '../../../../../src/domain/xtm-auth';
import { getHttpClient } from '../../../../../src/utils/http-client';
import { AUTOMATION_MANAGER_USER, SYSTEM_USER } from '../../../../../src/utils/access';
import { internalLoadById } from '../../../../../src/database/middleware-loader';
import { ENTITY_TYPE_USER } from '../../../../../src/schema/internalObject';
import { OPENCTI_ADMIN_UUID } from '../../../../../src/schema/general';
import {
  AGENT_CALL_TIMEOUT_MS,
  assertDefinitionRunAsAllowed,
  assertRunAsUserAllowed,
  buildAgentMessageContent,
  buildAgentSlugOneOf,
  buildPlaybookAutomationContext,
  callXtmAgent,
  isAgentBoundToIntent,
  isRunAsUserAllowed,
  resolveRunAsUserId,
  sanitizeDefinitionRunAs,
} from '../../../../../src/modules/playbook/components/ai-agent-shared';
import type { StixBundle } from '../../../../../src/types/stix-2-1-common';

// ── Fixtures ────────────────────────────────────────────────────────────

const baseBundle = { id: 'bundle--1', spec_version: '2.1', type: 'bundle', objects: [] } as unknown as StixBundle;

describe('ai-agent-shared', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('AGENT_CALL_TIMEOUT_MS', () => {
    it('should be at least the chatbot proxy timeout to allow long agent runs', () => {
      // 5 minutes; documented as "well above the default 2-minute httpClient cap".
      expect(AGENT_CALL_TIMEOUT_MS).toBeGreaterThanOrEqual(2 * 60 * 1000);
    });
  });

  describe('buildPlaybookAutomationContext', () => {
    it('should run as the platform-internal AUTOMATION_MANAGER_USER so XTM One sees a stable subject', () => {
      const context = buildPlaybookAutomationContext();
      expect(context.user).toBe(AUTOMATION_MANAGER_USER);
    });
  });

  describe('buildAgentMessageContent', () => {
    it('should serialize the bundle and prepend the bundle separator when no user prompt is given', () => {
      const content = buildAgentMessageContent(baseBundle);
      expect(content.startsWith('--- STIX BUNDLE ---\n')).toBe(true);
      // Strip the separator and reparse — we should get the bundle back unchanged.
      const json = content.replace(/^--- STIX BUNDLE ---\n/, '');
      expect(JSON.parse(json)).toEqual(baseBundle);
    });

    it('should treat a whitespace-only prompt as no prompt', () => {
      const content = buildAgentMessageContent(baseBundle, '   \n  ');
      expect(content.startsWith('--- STIX BUNDLE ---\n')).toBe(true);
    });

    it('should prepend a trimmed user instruction followed by a blank line and the bundle', () => {
      const content = buildAgentMessageContent(baseBundle, '  Tag every indicator with `auto-tagged`  ');
      expect(content.startsWith('Tag every indicator with `auto-tagged`\n\n--- STIX BUNDLE ---\n')).toBe(true);
    });
  });

  describe('buildAgentSlugOneOf', () => {
    it('should call XTM One as AUTOMATION_MANAGER_USER for the catalog lookup', async () => {
      vi.mocked(xtmOneClient.listAgentsForIntent).mockResolvedValue([]);

      await buildAgentSlugOneOf('cti.stix_transformer');

      expect(xtmOneClient.listAgentsForIntent).toHaveBeenCalledTimes(1);
      const passedContext = vi.mocked(xtmOneClient.listAgentsForIntent).mock.calls[0][0];
      expect(passedContext.user).toBe(AUTOMATION_MANAGER_USER);
      expect(vi.mocked(xtmOneClient.listAgentsForIntent).mock.calls[0][1]).toBe('cti.stix_transformer');
    });

    it('should map XTM One agents to JSON Schema oneOf entries sorted by title case-insensitively', async () => {
      vi.mocked(xtmOneClient.listAgentsForIntent).mockResolvedValue([
        { agent_id: '1', agent_name: 'beta', agent_slug: 'beta-slug', agent_description: null, priority: 0 },
        { agent_id: '2', agent_name: 'Alpha', agent_slug: 'alpha-slug', agent_description: null, priority: 0 },
      ]);

      const result = await buildAgentSlugOneOf('cti.stix_transformer');

      expect(result).toEqual([
        { const: 'alpha-slug', title: 'Alpha' },
        { const: 'beta-slug', title: 'beta' },
      ]);
    });

    it('should drop agents without a slug (cannot be invoked over the chat API)', async () => {
      vi.mocked(xtmOneClient.listAgentsForIntent).mockResolvedValue([
        { agent_id: '1', agent_name: 'Slugless', agent_slug: null, agent_description: null, priority: 0 },
        { agent_id: '2', agent_name: 'Real', agent_slug: 'real-slug', agent_description: null, priority: 0 },
      ]);

      const result = await buildAgentSlugOneOf('cti.stix_transformer');

      expect(result).toEqual([{ const: 'real-slug', title: 'Real' }]);
    });

    it('should return an empty array when the catalog call throws (form still renders cleanly)', async () => {
      vi.mocked(xtmOneClient.listAgentsForIntent).mockRejectedValue(new Error('XTM One down'));

      const result = await buildAgentSlugOneOf('cti.stix_transformer');

      expect(result).toEqual([]);
    });
  });

  describe('isAgentBoundToIntent', () => {
    const ADMIN_JWT_USER = { id: OPENCTI_ADMIN_UUID, user_email: 'admin@opencti.io' };

    beforeEach(() => {
      // No run-as user configured by default -> the seeded admin is resolved.
      vi.mocked(internalLoadById).mockResolvedValue(ADMIN_JWT_USER as any);
    });

    it('should return false (without calling XTM One) when the slug is empty', async () => {
      const result = await isAgentBoundToIntent('cti.stix_transformer', '');
      expect(result).toBe(false);
      expect(xtmOneClient.listAgentsForIntent).not.toHaveBeenCalled();
    });

    it('should return true when the slug is in the intent catalog', async () => {
      vi.mocked(xtmOneClient.listAgentsForIntent).mockResolvedValue([
        { agent_id: '1', agent_name: 'A', agent_slug: 'agent-a', agent_description: null, priority: 0 },
        { agent_id: '2', agent_name: 'B', agent_slug: 'agent-b', agent_description: null, priority: 0 },
      ]);

      const result = await isAgentBoundToIntent('cti.stix_transformer', 'agent-b');

      expect(result).toBe(true);
    });

    it('should query the catalog as the seeded admin when no run-as user is configured (same identity as the agent call)', async () => {
      vi.mocked(xtmOneClient.listAgentsForIntent).mockResolvedValue([]);

      await isAgentBoundToIntent('cti.stix_transformer', 'agent-a');

      expect(internalLoadById).toHaveBeenCalledWith(
        expect.anything(),
        SYSTEM_USER,
        OPENCTI_ADMIN_UUID,
        { type: ENTITY_TYPE_USER },
      );
      const passedContext = vi.mocked(xtmOneClient.listAgentsForIntent).mock.calls[0][0];
      expect(passedContext.user?.id).toBe(OPENCTI_ADMIN_UUID);
      expect(passedContext.user?.user_email).toBe('admin@opencti.io');
    });

    it('should query the catalog as the resolved run-as user when a runAsUserId is provided', async () => {
      vi.mocked(internalLoadById).mockResolvedValue({ id: 'user-7', user_email: 'analyst@org.test' } as any);
      vi.mocked(xtmOneClient.listAgentsForIntent).mockResolvedValue([
        { agent_id: '1', agent_name: 'A', agent_slug: 'agent-a', agent_description: null, priority: 0 },
      ]);

      const result = await isAgentBoundToIntent('cti.stix_transformer', 'agent-a', 'user-7');

      expect(result).toBe(true);
      expect(internalLoadById).toHaveBeenCalledWith(
        expect.anything(),
        SYSTEM_USER,
        'user-7',
        { type: ENTITY_TYPE_USER },
      );
      const passedContext = vi.mocked(xtmOneClient.listAgentsForIntent).mock.calls[0][0];
      expect(passedContext.user?.id).toBe('user-7');
      expect(passedContext.user?.user_email).toBe('analyst@org.test');
    });

    it('should fall back to AUTOMATION_MANAGER_USER when the run-as user cannot be loaded', async () => {
      vi.mocked(internalLoadById).mockResolvedValue(null as any);
      vi.mocked(xtmOneClient.listAgentsForIntent).mockResolvedValue([]);

      await isAgentBoundToIntent('cti.stix_transformer', 'agent-a', 'missing-user');

      const passedContext = vi.mocked(xtmOneClient.listAgentsForIntent).mock.calls[0][0];
      expect(passedContext.user?.id).toBe(AUTOMATION_MANAGER_USER.id);
      expect(passedContext.user?.user_email).toBe(AUTOMATION_MANAGER_USER.user_email);
    });

    it('should return false when the slug is NOT in the intent catalog (defense-in-depth check fails closed)', async () => {
      vi.mocked(xtmOneClient.listAgentsForIntent).mockResolvedValue([
        { agent_id: '1', agent_name: 'A', agent_slug: 'agent-a', agent_description: null, priority: 0 },
      ]);

      const result = await isAgentBoundToIntent('cti.stix_transformer', 'agent-not-bound');

      expect(result).toBe(false);
    });

    it('should fail closed (return false) when the catalog call throws', async () => {
      vi.mocked(xtmOneClient.listAgentsForIntent).mockRejectedValue(new Error('XTM One down'));

      const result = await isAgentBoundToIntent('cti.stix_transformer', 'agent-a');

      expect(result).toBe(false);
    });
  });

  describe('resolveRunAsUserId', () => {
    it('should return undefined when no run-as value is set', () => {
      expect(resolveRunAsUserId(undefined)).toBeUndefined();
      expect(resolveRunAsUserId(null)).toBeUndefined();
      expect(resolveRunAsUserId('')).toBeUndefined();
      expect(resolveRunAsUserId('   ')).toBeUndefined();
      expect(resolveRunAsUserId({})).toBeUndefined();
      expect(resolveRunAsUserId({ value: '   ' })).toBeUndefined();
    });

    it('should return the trimmed id from a raw string value', () => {
      expect(resolveRunAsUserId('  user-1  ')).toBe('user-1');
    });

    it('should return the trimmed value from a member-picker option object', () => {
      expect(resolveRunAsUserId({ label: 'Alice', value: '  user-2 ' })).toBe('user-2');
    });
  });

  describe('assertRunAsUserAllowed', () => {
    const context = { source: 'test' } as any;
    const author = { id: 'author-1' } as any;

    it('should allow (without a DB lookup) when no run-as user is configured', async () => {
      await expect(assertRunAsUserAllowed(context, author, null)).resolves.toBeUndefined();
      await expect(assertRunAsUserAllowed(context, author, undefined)).resolves.toBeUndefined();
      await expect(assertRunAsUserAllowed(context, author, { label: '', value: '' })).resolves.toBeUndefined();
      expect(internalLoadById).not.toHaveBeenCalled();
    });

    it('should allow the current (authenticated) author without a DB lookup', async () => {
      await expect(assertRunAsUserAllowed(context, author, { label: 'Me', value: 'author-1' })).resolves.toBeUndefined();
      expect(internalLoadById).not.toHaveBeenCalled();
    });

    it('should allow a service account target', async () => {
      vi.mocked(internalLoadById).mockResolvedValue({ id: 'svc-1', user_service_account: true } as any);

      await expect(assertRunAsUserAllowed(context, author, { label: 'Service', value: 'svc-1' })).resolves.toBeUndefined();
      expect(internalLoadById).toHaveBeenCalledWith(
        expect.anything(),
        SYSTEM_USER,
        'svc-1',
        { type: ENTITY_TYPE_USER },
      );
    });

    it('should refuse a regular (non-service-account) user', async () => {
      vi.mocked(internalLoadById).mockResolvedValue({ id: 'user-2', user_service_account: false } as any);

      await expect(assertRunAsUserAllowed(context, author, { label: 'Bob', value: 'user-2' }))
        .rejects.toThrow(/service account/);
    });

    it('should refuse (fail closed) when the run-as user cannot be loaded', async () => {
      vi.mocked(internalLoadById).mockResolvedValue(null as any);

      await expect(assertRunAsUserAllowed(context, author, 'ghost-user'))
        .rejects.toThrow(/service account/);
    });
  });

  describe('isRunAsUserAllowed', () => {
    const context = { source: 'test' } as any;
    const author = { id: 'author-1' } as any;

    it('should allow (without a DB lookup) an unset run-as or the current author', async () => {
      await expect(isRunAsUserAllowed(context, author, null)).resolves.toBe(true);
      await expect(isRunAsUserAllowed(context, author, { label: 'Me', value: 'author-1' })).resolves.toBe(true);
      expect(internalLoadById).not.toHaveBeenCalled();
    });

    it('should allow a service account and refuse a regular or unknown user', async () => {
      vi.mocked(internalLoadById).mockImplementation((async (_context: any, _user: any, id: string) => {
        if (id === 'svc-1') return { id, user_service_account: true };
        if (id === 'user-2') return { id, user_service_account: false };
        return null;
      }) as any);

      await expect(isRunAsUserAllowed(context, author, 'svc-1')).resolves.toBe(true);
      await expect(isRunAsUserAllowed(context, author, 'user-2')).resolves.toBe(false);
      await expect(isRunAsUserAllowed(context, author, 'ghost')).resolves.toBe(false);
    });
  });

  describe('assertDefinitionRunAsAllowed', () => {
    const context = { source: 'test' } as any;
    const author = { id: 'author-1' } as any;

    const definitionWith = (runAsValues: Array<unknown>) => JSON.stringify({
      nodes: runAsValues.map((runAs, index) => ({
        id: `node-${index}`,
        name: `node-${index}`,
        position: { x: 0, y: 0 },
        component_id: 'PLAYBOOK_AI_AGENT_SEND_COMPONENT',
        configuration: JSON.stringify(runAs === undefined ? {} : { run_as: runAs }),
      })),
      links: [],
    });

    it('should resolve for an empty, missing or unparseable definition', async () => {
      await expect(assertDefinitionRunAsAllowed(context, author, undefined)).resolves.toBeUndefined();
      await expect(assertDefinitionRunAsAllowed(context, author, '{not json')).resolves.toBeUndefined();
      await expect(assertDefinitionRunAsAllowed(context, author, definitionWith([]))).resolves.toBeUndefined();
      expect(internalLoadById).not.toHaveBeenCalled();
    });

    it('should resolve when every node targets the author, a service account or nothing', async () => {
      vi.mocked(internalLoadById).mockResolvedValue({ id: 'svc-1', user_service_account: true } as any);

      const definition = definitionWith([undefined, { label: 'Me', value: 'author-1' }, { label: 'Svc', value: 'svc-1' }]);
      await expect(assertDefinitionRunAsAllowed(context, author, definition)).resolves.toBeUndefined();
    });

    it('should reject when any node targets a regular user', async () => {
      vi.mocked(internalLoadById).mockResolvedValue({ id: 'user-2', user_service_account: false } as any);

      const definition = definitionWith([{ label: 'Me', value: 'author-1' }, { label: 'Bob', value: 'user-2' }]);
      await expect(assertDefinitionRunAsAllowed(context, author, definition)).rejects.toThrow(/service account/);
    });
  });

  describe('sanitizeDefinitionRunAs', () => {
    const context = { source: 'test' } as any;
    const author = { id: 'author-1', name: 'Author One' } as any;

    const parseNodeRunAs = (definition: string) => (JSON.parse(definition).nodes as Array<{ configuration: string }>)
      .map((node) => JSON.parse(node.configuration).run_as);

    it('should return the input unchanged when it is empty or unparseable', async () => {
      await expect(sanitizeDefinitionRunAs(context, author, null)).resolves.toBeNull();
      await expect(sanitizeDefinitionRunAs(context, author, '{not json')).resolves.toBe('{not json');
      expect(internalLoadById).not.toHaveBeenCalled();
    });

    it('should keep allowed targets and reset disallowed ones to the acting user', async () => {
      vi.mocked(internalLoadById).mockImplementation((async (_context: any, _user: any, id: string) => {
        if (id === 'svc-1') return { id, user_service_account: true };
        return { id, user_service_account: false };
      }) as any);

      const definition = JSON.stringify({
        nodes: [
          { id: 'a', name: 'a', position: { x: 0, y: 0 }, component_id: 'C', configuration: JSON.stringify({ run_as: { label: 'Me', value: 'author-1' } }) },
          { id: 'b', name: 'b', position: { x: 0, y: 0 }, component_id: 'C', configuration: JSON.stringify({ run_as: { label: 'Svc', value: 'svc-1' } }) },
          { id: 'c', name: 'c', position: { x: 0, y: 0 }, component_id: 'C', configuration: JSON.stringify({ run_as: { label: 'Bob', value: 'user-2' } }) },
          { id: 'd', name: 'd', position: { x: 0, y: 0 }, component_id: 'C', configuration: JSON.stringify({ other: true }) },
        ],
        links: [],
      });

      const sanitized = await sanitizeDefinitionRunAs(context, author, definition);
      expect(sanitized).not.toBe(definition);
      const [a, b, c, d] = parseNodeRunAs(sanitized as string);
      expect(a).toEqual({ label: 'Me', value: 'author-1' });
      expect(b).toEqual({ label: 'Svc', value: 'svc-1' });
      expect(c).toEqual({ label: 'Author One', value: 'author-1' });
      expect(d).toBeUndefined();
    });

    it('should return the original string when nothing has to change', async () => {
      vi.mocked(internalLoadById).mockResolvedValue({ id: 'svc-1', user_service_account: true } as any);

      const definition = JSON.stringify({
        nodes: [
          { id: 'a', name: 'a', position: { x: 0, y: 0 }, component_id: 'C', configuration: JSON.stringify({ run_as: { label: 'Svc', value: 'svc-1' } }) },
        ],
        links: [],
      });

      await expect(sanitizeDefinitionRunAs(context, author, definition)).resolves.toBe(definition);
    });
  });

  describe('callXtmAgent', () => {
    const ADMIN_JWT_USER = { id: OPENCTI_ADMIN_UUID, user_email: 'admin@opencti.io' };

    beforeEach(() => {
      vi.mocked(issueXtmJwt).mockResolvedValue('signed.jwt');
      vi.mocked(xtmOneClient.isConfigured).mockReturnValue(true);
      vi.mocked(nconf.get).mockReturnValue('https://xtm-one.test');
      // No run-as user configured by default -> the seeded admin is resolved.
      vi.mocked(internalLoadById).mockResolvedValue(ADMIN_JWT_USER as any);
    });

    it('should return null and not call the HTTP client when XTM One is not configured', async () => {
      vi.mocked(nconf.get).mockReturnValue(undefined);
      vi.mocked(xtmOneClient.isConfigured).mockReturnValue(false);

      const result = await callXtmAgent('any-agent', 'content');

      expect(result).toBeNull();
      expect(getHttpClient).not.toHaveBeenCalled();
    });

    it('should default to the seeded admin and POST a non-streaming chat message', async () => {
      const post = vi.fn().mockResolvedValue({ data: { content: 'agent reply' } });
      vi.mocked(getHttpClient).mockReturnValue({ post } as any);

      const result = await callXtmAgent('agent-slug', 'hello world');

      expect(result).toBe('agent reply');
      // No run-as user -> resolve the seeded admin by its fixed UUID.
      expect(internalLoadById).toHaveBeenCalledWith(
        expect.anything(),
        SYSTEM_USER,
        OPENCTI_ADMIN_UUID,
        { type: ENTITY_TYPE_USER },
      );
      expect(issueXtmJwt).toHaveBeenCalledWith(ADMIN_JWT_USER, 'https://xtm-one.test');
      expect(getHttpClient).toHaveBeenCalledTimes(1);
      const headers = vi.mocked(getHttpClient).mock.calls[0][0].headers as Record<string, string>;
      expect(headers.Authorization).toBe('Bearer signed.jwt');
      expect(headers['X-Platform-Product']).toBe('opencti');
      expect(post).toHaveBeenCalledWith(
        '/api/v1/platform/chat/messages',
        { agent_slug: 'agent-slug', content: 'hello world', stream: false },
        { timeout: AGENT_CALL_TIMEOUT_MS },
      );
    });

    it('should mint the JWT for the resolved run-as user when a runAsUserId is provided', async () => {
      vi.mocked(internalLoadById).mockResolvedValue({ id: 'user-7', user_email: 'analyst@org.test' } as any);
      const post = vi.fn().mockResolvedValue({ data: { content: 'ok' } });
      vi.mocked(getHttpClient).mockReturnValue({ post } as any);

      const result = await callXtmAgent('agent-slug', 'content', 'user-7');

      expect(result).toBe('ok');
      expect(internalLoadById).toHaveBeenCalledWith(
        expect.anything(),
        SYSTEM_USER,
        'user-7',
        { type: ENTITY_TYPE_USER },
      );
      expect(issueXtmJwt).toHaveBeenCalledWith({ id: 'user-7', user_email: 'analyst@org.test' }, 'https://xtm-one.test');
    });

    it('should fall back to AUTOMATION_MANAGER_USER when the run-as user cannot be loaded', async () => {
      vi.mocked(internalLoadById).mockResolvedValue(null as any);
      const post = vi.fn().mockResolvedValue({ data: { content: 'ok' } });
      vi.mocked(getHttpClient).mockReturnValue({ post } as any);

      await callXtmAgent('agent-slug', 'content', 'missing-user');

      expect(issueXtmJwt).toHaveBeenCalledWith(AUTOMATION_MANAGER_USER, 'https://xtm-one.test');
    });

    it('should fall back to AUTOMATION_MANAGER_USER when the resolved user has no email', async () => {
      vi.mocked(internalLoadById).mockResolvedValue({ id: 'user-9' } as any);
      const post = vi.fn().mockResolvedValue({ data: { content: 'ok' } });
      vi.mocked(getHttpClient).mockReturnValue({ post } as any);

      await callXtmAgent('agent-slug', 'content', 'user-9');

      expect(issueXtmJwt).toHaveBeenCalledWith(AUTOMATION_MANAGER_USER, 'https://xtm-one.test');
    });

    it('should fall back to AUTOMATION_MANAGER_USER when resolving the run-as user throws', async () => {
      vi.mocked(internalLoadById).mockRejectedValue(new Error('ES down'));
      const post = vi.fn().mockResolvedValue({ data: { content: 'ok' } });
      vi.mocked(getHttpClient).mockReturnValue({ post } as any);

      await callXtmAgent('agent-slug', 'content', 'user-x');

      expect(issueXtmJwt).toHaveBeenCalledWith(AUTOMATION_MANAGER_USER, 'https://xtm-one.test');
    });

    it('should return null when the assistant content field is missing', async () => {
      const post = vi.fn().mockResolvedValue({ data: {} });
      vi.mocked(getHttpClient).mockReturnValue({ post } as any);

      const result = await callXtmAgent('agent-slug', 'content');

      expect(result).toBeNull();
    });

    it('should swallow network errors and return null instead of throwing (playbook stays alive)', async () => {
      const post = vi.fn().mockRejectedValue(new Error('ECONNREFUSED'));
      vi.mocked(getHttpClient).mockReturnValue({ post } as any);

      const result = await callXtmAgent('agent-slug', 'content');

      expect(result).toBeNull();
    });
  });
});
