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
  executionContext: vi.fn((source: string) => ({ source })),
}));

// ── Imports (after mocks) ───────────────────────────────────────────────

import nconf from 'nconf';
import xtmOneClient from '../../../../../src/modules/xtm/one/xtm-one-client';
import { issueXtmJwt } from '../../../../../src/domain/xtm-auth';
import { getHttpClient } from '../../../../../src/utils/http-client';
import { AUTOMATION_MANAGER_USER } from '../../../../../src/utils/access';
import {
  AGENT_CALL_TIMEOUT_MS,
  buildAgentMessageContent,
  buildAgentSlugOneOf,
  buildPlaybookAutomationContext,
  callXtmAgent,
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

  describe('callXtmAgent', () => {
    beforeEach(() => {
      vi.mocked(issueXtmJwt).mockResolvedValue('signed.jwt');
      vi.mocked(xtmOneClient.isConfigured).mockReturnValue(true);
      vi.mocked(nconf.get).mockReturnValue('https://xtm-one.test');
    });

    it('should return null and not call the HTTP client when XTM One is not configured', async () => {
      vi.mocked(nconf.get).mockReturnValue(undefined);
      vi.mocked(xtmOneClient.isConfigured).mockReturnValue(false);

      const result = await callXtmAgent('any-agent', 'content');

      expect(result).toBeNull();
      expect(getHttpClient).not.toHaveBeenCalled();
    });

    it('should mint the JWT as AUTOMATION_MANAGER_USER and POST a non-streaming chat message', async () => {
      const post = vi.fn().mockResolvedValue({ data: { content: 'agent reply' } });
      vi.mocked(getHttpClient).mockReturnValue({ post } as any);

      const result = await callXtmAgent('agent-slug', 'hello world');

      expect(result).toBe('agent reply');
      expect(issueXtmJwt).toHaveBeenCalledWith(AUTOMATION_MANAGER_USER, 'https://xtm-one.test');
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
