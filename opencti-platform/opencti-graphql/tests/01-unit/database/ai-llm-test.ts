import { describe, expect, it, vi } from 'vitest';

const chatMistralAiCtor = vi.fn();
const chatOpenAiCtor = vi.fn();
const mistralCtor = vi.fn();

vi.mock('@langchain/mistralai', () => {
  return {
    ChatMistralAI: chatMistralAiCtor,
  };
});

vi.mock('@langchain/openai', () => {
  return {
    ChatOpenAI: chatOpenAiCtor,
    AzureChatOpenAI: vi.fn(),
  };
});

vi.mock('@mistralai/mistralai', () => {
  return {
    Mistral: mistralCtor,
  };
});

vi.mock('openai', () => {
  class AuthenticationError extends Error {}
  return {
    AuthenticationError,
    OpenAI: vi.fn(),
    AzureOpenAI: vi.fn(),
  };
});

vi.mock('../../../src/config/conf', async (importOriginal) => {
  const actual: any = await importOriginal();
  return {
    ...actual,
    default: {
      get: (key: string) => {
        switch (key) {
          case 'ai:enabled':
            return true;
          case 'ai:type':
            return 'mistralai';
          case 'ai:endpoint':
            return undefined;
          case 'ai:token':
            return 'test-token';
          case 'ai:model':
            return 'mistral-large-latest';
          case 'ai:max_tokens':
            return 256;
          case 'ai:version':
            return undefined;
          case 'ai:ai_azure_instance':
            return undefined;
          case 'ai:ai_azure_deployment':
            return undefined;
          default:
            return undefined;
        }
      },
    },
    BUS_TOPICS: {},
    logApp: {
      debug: vi.fn(),
      info: vi.fn(),
      warn: vi.fn(),
      error: vi.fn(),
    },
  };
});

describe('ai-llm initialization', () => {
  it('should not throw and should use ChatMistralAI when endpoint is empty', async () => {
    vi.resetModules();

    await expect(import('../../../src/database/ai-llm')).resolves.toBeDefined();

    expect(chatMistralAiCtor).toHaveBeenCalledTimes(1);
    expect(chatOpenAiCtor).not.toHaveBeenCalled();
  });
});
