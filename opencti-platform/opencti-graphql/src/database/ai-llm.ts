import type { ChatPromptValueInterface } from '@langchain/core/prompt_values';
import { ChatMistralAI } from '@langchain/mistralai';
import { AzureChatOpenAI, ChatOpenAI } from '@langchain/openai';
import { Mistral } from '@mistralai/mistralai';
import type { ChatCompletionStreamRequest } from '@mistralai/mistralai/models/components';
import { AuthenticationError, AzureOpenAI, OpenAI } from 'openai';
import { HumanMessage } from '@langchain/core/messages';
import conf, { BUS_TOPICS, logApp } from '../config/conf';
import { UnknownError, UnsupportedError } from '../config/errors';
import { OutputSchema } from '../modules/ai/ai-nlq-schema';
import type { Output } from '../modules/ai/ai-nlq-schema';
import { AI_BUS } from '../modules/ai/ai-types';
import type { AuthUser } from '../types/user';
import { truncate } from '../utils/format';
import { notify } from './redis';
import { isEmptyField } from './utils';
import { addNlqQueryCount } from '../manager/telemetryManager';

// Helper to safely extract error message for logging
function getErrorMessage(err: unknown): string {
  if (typeof err === 'object' && err !== null && 'message' in err && typeof (err as any).message === 'string') {
    return (err as any).message;
  }
  return String(err);
}

const AI_ENABLED = conf.get('ai:enabled');
const AI_TYPE = conf.get('ai:type');
const AI_ENDPOINT = conf.get('ai:endpoint');
const AI_TOKEN = conf.get('ai:token');
const AI_MODEL = conf.get('ai:model');
const AI_MAX_TOKENS = conf.get('ai:max_tokens');
const AI_VERSION = conf.get('ai:version');
const AI_AZURE_INSTANCE = conf.get('ai:ai_azure_instance');
const AI_AZURE_DEPLOYMENT = conf.get('ai:ai_azure_deployment');

// Utility to log AI configuration (excluding sensitive info)
function logAiConfig() {
  logApp.info('[AI] Configuration', {
    enabled: AI_ENABLED,
    type: AI_TYPE,
    endpoint: AI_ENDPOINT,
    model: AI_MODEL,
    version: AI_VERSION,
    azure_instance: AI_AZURE_INSTANCE,
    azure_deployment: AI_AZURE_DEPLOYMENT,
    // Do NOT log AI_TOKEN or secrets
  });
}

// Utility to validate OpenAI-compatible connection with a minimal test call
async function validateOpenAIConnection(
  aiClient: OpenAI | AzureOpenAI,
  throwOnError = false
): Promise<boolean> {
  // Azure OpenAI endpoint misconfiguration check
  if (typeof AI_ENDPOINT === 'string' && /\/openai\/deployments\//.test(AI_ENDPOINT)) {
    const msg = `\n[AI] Detected Azure OpenAI endpoint misconfiguration.\nYour endpoint is set to: ${AI_ENDPOINT}\nIt should be the base instance URL (e.g. https://YOUR-RESOURCE-NAME.openai.azure.com/), not the full deployment path.\nSet 'ai:endpoint' to the base URL, and 'ai:ai_azure_deployment' to your deployment name.\nSee: https://learn.microsoft.com/en-us/azure/ai-services/openai/reference#rest-api-versioning\n`;
    logApp.error(msg);
    if (throwOnError) throw new Error(msg);
    return false;
  }
  try {
    await aiClient.chat.completions.create({
      model: AI_MODEL,
      messages: [{ role: 'user', content: 'ping' }],
      max_tokens: 1,
    });
    logApp.info(`[AI] OpenAI-compatible connection succeeded (model: ${AI_MODEL}, endpoint: ${AI_ENDPOINT}, deployment: ${AI_AZURE_DEPLOYMENT || 'n/a'})`);
    return true;
  } catch (error: any) {
    logApp.error(`[AI] OpenAI-compatible connection failed (model: ${AI_MODEL}, endpoint: ${AI_ENDPOINT}, deployment: ${AI_AZURE_DEPLOYMENT || 'n/a'})`);
    if (error.code === 'ENOTFOUND') {
      logApp.error(`- Cannot reach endpoint: ${AI_ENDPOINT}. Check 'ai:endpoint' in your configuration.`);
      logApp.error('  Suggestion: Verify DNS, proxy, and firewall settings for this endpoint.');
    } else if (error.code === 'ETIMEDOUT') {
      logApp.error(`- Connection to endpoint timed out: ${AI_ENDPOINT}. Check network/firewall settings.`);
      logApp.error('  Suggestion: Ensure the endpoint is reachable and not blocked by a firewall or proxy.');
    } else if (error.response) {
      const { status, data } = error.response;
      logApp.error(`- HTTP Status: ${status}`);
      if (status === 401) {
        logApp.error('- Authentication failed. Check \'ai:token\'.');
        logApp.error('  Suggestion: Ensure your API token is correct and has not expired.');
      } else if (status === 403) {
        logApp.error(`- Forbidden. Verify access rights or deployment ('ai:ai_azure_deployment': ${AI_AZURE_DEPLOYMENT}).`);
        logApp.error('  Suggestion: Ensure your token has access to the deployment and model specified.');
      } else if (status === 404) {
        logApp.error(`- Resource not found. Check model ('ai:model': ${AI_MODEL}) or deployment ('ai:ai_azure_deployment': ${AI_AZURE_DEPLOYMENT}).`);
        logApp.error('  Suggestion: Verify the model and deployment names are correct and exist in your Azure/OpenAI account.');
      } else if (status === 429) {
        logApp.error('- Rate limit exceeded. Reduce request frequency or check your subscription limits.');
        logApp.error('  Suggestion: Wait and retry, or upgrade your subscription if needed.');
      } else if (status >= 500) {
        logApp.error('- Server error from AI provider. Try again later or check provider status.');
      } else {
        logApp.error(`- Error response: ${JSON.stringify(data)}`);
      }
    } else if (error.message) {
      logApp.error(`- Message: ${error.message}`);
      if (error.message.includes('self signed certificate')) {
        logApp.error('  Suggestion: If using a self-signed certificate, set NODE_TLS_REJECT_UNAUTHORIZED=0 for testing (not recommended for production).');
      }
    } else {
      logApp.error(`- Unknown error: ${error}`);
    }
    logApp.error('[AI] Troubleshooting summary:');
    logApp.error('  - Check your configuration values in config or environment variables.');
    logApp.error('  - Confirm network connectivity to the endpoint.');
    logApp.error('  - Validate your API token and permissions.');
    logApp.error('  - Ensure the model and deployment names are correct.');
    logApp.error('  - Review provider status for outages or rate limits.');
    if (throwOnError) throw new Error(`[AI] Initialization failed: ${error.message || error}`);
    return false;
  }
}

// Update validateLangChainChat for type safety
async function validateLangChainChat(chatModel: ChatOpenAI | ChatMistralAI | AzureChatOpenAI) {
  try {
    // Use a HumanMessage directly, as .invoke() expects a BaseMessage[] or string
    await chatModel.invoke([new HumanMessage('ping')]);
    logApp.info(`[AI] LangChain chat model integration validated successfully (model: ${AI_MODEL}, endpoint: ${AI_ENDPOINT}, deployment: ${AI_AZURE_DEPLOYMENT || 'n/a'})`);
  } catch (err: any) {
    logApp.error('[AI] LangChain chat model validation failed.');
    logApp.error(`- Message: ${err.message}`);
    logApp.error(`- Model: ${AI_MODEL}, Endpoint: ${AI_ENDPOINT}, Deployment: ${AI_AZURE_DEPLOYMENT || 'n/a'}`);
    logApp.error('[AI] Troubleshooting summary:');
    logApp.error('  - Ensure LangChain is configured with the correct model and endpoint.');
    logApp.error('  - Check upstream OpenAI/AzureOpenAI connectivity.');
    throw new Error(`[AI] LangChain chat model validation failed: ${err.message}`);
  }
}

// Call at startup
logAiConfig();

// Extensible AI provider registry
type AIProviderInit = () => Promise<{ client: any, nlqChat: ChatOpenAI | ChatMistralAI | AzureChatOpenAI }>;

const AI_PROVIDERS: Record<string, AIProviderInit> = {
  mistralai: async () => {
    const mistralClient = new Mistral({
      serverURL: isEmptyField(AI_ENDPOINT) ? undefined : AI_ENDPOINT,
      apiKey: AI_TOKEN,
    });
    let nlq: ChatMistralAI | ChatOpenAI;
    if (AI_ENDPOINT.includes('https://api.mistral.ai')) {
      nlq = new ChatMistralAI({
        model: AI_MODEL,
        apiKey: AI_TOKEN,
        temperature: 0,
      });
    } else {
      nlq = new ChatOpenAI({
        model: AI_MODEL,
        apiKey: AI_TOKEN,
        temperature: 0,
        configuration: {
          baseURL: `${AI_ENDPOINT}/v1`,
        },
      });
    }
    await validateLangChainChat(nlq);
    return { client: mistralClient, nlqChat: nlq };
  },
  openai: async () => {
    const openaiClient = new OpenAI({
      apiKey: AI_TOKEN,
      ...(isEmptyField(AI_ENDPOINT) ? {} : { baseURL: AI_ENDPOINT }),
    });
    await validateOpenAIConnection(openaiClient, true);
    const nlq = new ChatOpenAI({
      model: AI_MODEL,
      apiKey: AI_TOKEN,
      temperature: 0,
      configuration: {
        baseURL: AI_ENDPOINT || undefined,
      },
    });
    await validateLangChainChat(nlq);
    return { client: openaiClient, nlqChat: nlq };
  },
  azureopenai: async () => {
    const azureClient = new AzureOpenAI({
      apiKey: AI_TOKEN,
      endpoint: AI_ENDPOINT,
      apiVersion: AI_VERSION,
      deployment: AI_AZURE_DEPLOYMENT,
    });
    await validateOpenAIConnection(azureClient, true);
    const nlq = new AzureChatOpenAI({
      azureOpenAIApiKey: AI_TOKEN,
      azureOpenAIApiVersion: AI_VERSION,
      azureOpenAIApiInstanceName: AI_AZURE_INSTANCE,
      azureOpenAIApiDeploymentName: AI_AZURE_DEPLOYMENT,
      temperature: 0,
    });
    await validateLangChainChat(nlq);
    return { client: azureClient, nlqChat: nlq };
  }
  // Add new providers here
};

// Guard variables for initialization
let client: Mistral | OpenAI | AzureOpenAI | null = null;
let nlqChat: ChatOpenAI | ChatMistralAI | AzureChatOpenAI | null = null;
let aiInitPromise: Promise<void> | null = null;
let aiInitialized = false;

// Helper for resetting aiInitPromise on failure
function resetAIInitPromiseOnFailure() {
  aiInitPromise = null;
  aiInitialized = false;
}

// Refactored async initialization with concurrency/re-init guard
export async function initializeAIClients() {
  logApp.info('[AI] Starting AI client initialization...');
  if (aiInitialized) {
    logApp.info('[AI] Already initialized, skipping re-initialization.');
    return;
  }
  if (aiInitPromise) {
    logApp.info('[AI] Initialization already in progress, awaiting completion.');
    await aiInitPromise;
    return;
  }
  aiInitPromise = (async () => {
    logApp.info('[AI] AI client initialization triggered.', {
      enabled: AI_ENABLED,
      type: AI_TYPE,
      endpoint: AI_ENDPOINT,
      model: AI_MODEL,
      version: AI_VERSION,
      azure_instance: AI_AZURE_INSTANCE,
      azure_deployment: AI_AZURE_DEPLOYMENT,
    });
    if (AI_ENABLED && AI_TOKEN) {
      try {
        const providerInit = AI_PROVIDERS[AI_TYPE];
        if (!providerInit) {
          logApp.error('[AI] Unsupported AI type in configuration', { type: AI_TYPE });
          resetAIInitPromiseOnFailure();
          throw UnsupportedError('Not supported AI type (currently support: mistralai, openai, azureopenai)', { type: AI_TYPE });
        }
        logApp.info(`[AI] Initializing provider: ${AI_TYPE}`);
        const { client: c, nlqChat: n } = await providerInit();
        client = c;
        nlqChat = n;
        aiInitialized = true;
        logApp.info('[AI] Initialization complete.');
      } catch (err) {
        logApp.error('[AI] Error initializing AI client', {
          error: err,
          enabled: AI_ENABLED,
          type: AI_TYPE,
          endpoint: AI_ENDPOINT,
          model: AI_MODEL,
          version: AI_VERSION,
          azure_instance: AI_AZURE_INSTANCE,
          azure_deployment: AI_AZURE_DEPLOYMENT,
        });
        resetAIInitPromiseOnFailure();
        // Always log the error before throwing
        logApp.error(`[AI] Initialization failed with error: ${getErrorMessage(err)}`);
        throw err;
      }
    } else {
      logApp.warn('[AI] AI is disabled or missing token/config, initialization skipped.', {
        enabled: AI_ENABLED,
        type: AI_TYPE,
        endpoint: AI_ENDPOINT,
        model: AI_MODEL,
        version: AI_VERSION,
        azure_instance: AI_AZURE_INSTANCE,
        azure_deployment: AI_AZURE_DEPLOYMENT,
      });
      resetAIInitPromiseOnFailure();
    }
  })();
  try {
    await aiInitPromise;
    logApp.info('[AI] AI client initialization finished.');
  } catch (err) {
    resetAIInitPromiseOnFailure();
    logApp.error(`[AI] AI client initialization threw an error: ${getErrorMessage(err)}`);
    throw err;
  }
}

// Health check endpoint logic
export function getAIHealthStatus() {
  return {
    initialized: aiInitialized,
    enabled: AI_ENABLED,
    type: AI_TYPE,
    endpoint: AI_ENDPOINT,
    model: AI_MODEL,
    version: AI_VERSION,
    azure_instance: AI_AZURE_INSTANCE,
    azure_deployment: AI_AZURE_DEPLOYMENT,
    clientReady: !!client,
    nlqChatReady: !!nlqChat,
  };
}

// Query MistralAI (Streaming)
export const queryMistralAi = async (busId: string | null, systemMessage: string, userMessage: string, user: AuthUser) => {
  await initializeAIClients();
  if (!client) {
    logApp.error('[AI] MistralAI client not initialized', {
      enabled: AI_ENABLED,
      type: AI_TYPE,
      endpoint: AI_ENDPOINT,
      model: AI_MODEL,
      version: AI_VERSION,
    });
    throw UnsupportedError('Incorrect AI configuration', { enabled: AI_ENABLED, type: AI_TYPE, endpoint: AI_ENDPOINT, model: AI_MODEL });
  }
  try {
    logApp.debug('[AI] Querying MistralAI with prompt', { questionStart: userMessage.substring(0, 100) });
    const request: ChatCompletionStreamRequest = {
      model: AI_MODEL,
      temperature: 0,
      messages: [
        { role: 'system', content: systemMessage },
        { role: 'user', content: truncate(userMessage, AI_MAX_TOKENS, false) },
      ],
    };
    const response = await (client as Mistral)?.chat.stream(request);
    let content = '';
    if (response) {
      // eslint-disable-next-line no-restricted-syntax
      for await (const chunk of response) {
        if (chunk.data.choices[0].delta.content !== undefined) {
          const streamText = chunk.data.choices[0].delta.content;
          content += streamText;
          if (busId !== null) {
            await notify(BUS_TOPICS[AI_BUS].EDIT_TOPIC, { bus_id: busId, content }, user);
          }
        }
      }
      return content;
    }
    logApp.error('[AI] No response from MistralAI', { busId, systemMessage, userMessage });
    return { error: true, message: 'No response from MistralAI' };
  } catch (err: any) {
    logApp.error('[AI] Cannot query MistralAI', { cause: err });
    return { error: true, message: err?.message || err?.toString() };
  }
};

// Query OpenAI (Streaming)
export const queryChatGpt = async (busId: string | null, developerMessage: string, userMessage: string, user: AuthUser) => {
  await initializeAIClients();
  if (!client) {
    logApp.error('[AI] OpenAI client not initialized', {
      enabled: AI_ENABLED,
      type: AI_TYPE,
      endpoint: AI_ENDPOINT,
      model: AI_MODEL,
      version: AI_VERSION,
    });
    throw UnsupportedError('Incorrect AI configuration', { enabled: AI_ENABLED, type: AI_TYPE, endpoint: AI_ENDPOINT, model: AI_MODEL });
  }
  try {
    logApp.info('[AI] Querying OpenAI with prompt', { type: AI_TYPE });
    const response = await (client as OpenAI)?.chat.completions.create({
      model: AI_MODEL,
      messages: [
        { role: (AI_TYPE === 'azureopenai') ? 'system' : 'developer', content: developerMessage },
        { role: 'user', content: truncate(userMessage, AI_MAX_TOKENS, false) }
      ],
      stream: true,
    });
    let content = '';
    if (response) {
      // eslint-disable-next-line no-restricted-syntax
      for await (const chunk of response) {
        if (chunk.choices[0]?.delta.content !== undefined) {
          const streamText = chunk.choices[0].delta.content;
          content += streamText;
          if (busId !== null) {
            await notify(BUS_TOPICS[AI_BUS].EDIT_TOPIC, { bus_id: busId, content }, user);
          }
        }
      }
      return content;
    }
    logApp.error('[AI] No response from OpenAI', { busId, developerMessage, userMessage });
    return { error: true, message: 'No response from OpenAI' };
  } catch (err: any) {
    logApp.error('[AI] Cannot query OpenAI', { cause: err });
    return { error: true, message: err?.message || err?.toString() };
  }
};

// Generic AI Query Handler
export const queryAi = async (busId: string | null, developerMessage: string | null, userMessage: string, user: AuthUser) => {
  await initializeAIClients();
  const finalDeveloperMessage = developerMessage || 'You are an assistant helping a cyber threat intelligence analyst to better understand cyber threat intelligence data.';
  switch (AI_TYPE) {
    case 'mistralai':
      return queryMistralAi(busId, finalDeveloperMessage, userMessage, user);
    case 'azureopenai':
    case 'openai':
      return queryChatGpt(busId, finalDeveloperMessage, userMessage, user);
    default:
      throw UnsupportedError('Not supported AI type', { type: AI_TYPE });
  }
};

// NLQ AI Query with LangChain's Chat Models
export const queryNLQAi = async (promptValue: ChatPromptValueInterface) => {
  await initializeAIClients();
  const badAiConfigError = UnsupportedError('Incorrect AI configuration for NLQ', {
    enabled: AI_ENABLED,
    type: AI_TYPE,
    endpoint: AI_ENDPOINT,
    model: AI_MODEL,
    version: AI_VERSION,
    azure_instance: AI_AZURE_INSTANCE,
    azure_deployment: AI_AZURE_DEPLOYMENT,
  });
  if (!nlqChat) {
    logApp.error('[NLQ] nlqChat not initialized', {
      enabled: AI_ENABLED,
      type: AI_TYPE,
      endpoint: AI_ENDPOINT,
      model: AI_MODEL,
      version: AI_VERSION,
      azure_instance: AI_AZURE_INSTANCE,
      azure_deployment: AI_AZURE_DEPLOYMENT,
    });
    throw badAiConfigError;
  }

  await addNlqQueryCount();

  logApp.info('[NLQ] Querying AI model for structured output');
  try {
    // Type narrowing: ensure nlqChat has withStructuredOutput
    if (typeof (nlqChat as any).withStructuredOutput === 'function') {
      const runnable = (nlqChat as any).withStructuredOutput(OutputSchema);
      return runnable.invoke(promptValue);
    }
    throw UnsupportedError('The current AI provider does not support structured output.', {
      type: AI_TYPE,
      model: AI_MODEL
    });
  } catch (err: any) {
    // More granular error handling for common API errors
    let errorType = 'UnknownError';
    const errorMessage = err?.message || err?.toString();
    const errorStatus = err?.response?.status;
    if (err instanceof AuthenticationError) {
      errorType = 'AuthenticationError';
      logApp.error('[NLQ] Authentication error when calling the NLQ model', {
        error: err,
        enabled: AI_ENABLED,
        type: AI_TYPE,
        endpoint: AI_ENDPOINT,
        model: AI_MODEL,
        version: AI_VERSION,
        azure_instance: AI_AZURE_INSTANCE,
        azure_deployment: AI_AZURE_DEPLOYMENT,
        promptValue
      });
      throw badAiConfigError;
    } else if (errorStatus === 429) {
      errorType = 'RateLimitError';
      logApp.error('[NLQ] Rate limit exceeded when calling the NLQ model', {
        error: err,
        enabled: AI_ENABLED,
        type: AI_TYPE,
        endpoint: AI_ENDPOINT,
        model: AI_MODEL,
        version: AI_VERSION,
        azure_instance: AI_AZURE_INSTANCE,
        azure_deployment: AI_AZURE_DEPLOYMENT,
        promptValue
      });
    } else if (errorStatus === 401 || errorStatus === 403) {
      errorType = 'AuthzError';
      logApp.error('[NLQ] Authorization error when calling the NLQ model', {
        error: err,
        enabled: AI_ENABLED,
        type: AI_TYPE,
        endpoint: AI_ENDPOINT,
        model: AI_MODEL,
        version: AI_VERSION,
        azure_instance: AI_AZURE_INSTANCE,
        azure_deployment: AI_AZURE_DEPLOYMENT,
        promptValue
      });
    } else if (errorStatus === 404) {
      errorType = 'NotFoundError';
      logApp.error('[NLQ] Model or deployment not found', {
        error: err,
        enabled: AI_ENABLED,
        type: AI_TYPE,
        endpoint: AI_ENDPOINT,
        model: AI_MODEL,
        version: AI_VERSION,
        azure_instance: AI_AZURE_INSTANCE,
        azure_deployment: AI_AZURE_DEPLOYMENT,
        promptValue
      });
    } else if (errorStatus && errorStatus >= 500) {
      errorType = 'ProviderServerError';
      logApp.error('[NLQ] Provider server error', {
        error: err,
        enabled: AI_ENABLED,
        type: AI_TYPE,
        endpoint: AI_ENDPOINT,
        model: AI_MODEL,
        version: AI_VERSION,
        azure_instance: AI_AZURE_INSTANCE,
        azure_deployment: AI_AZURE_DEPLOYMENT,
        promptValue
      });
    } else {
      logApp.error('[NLQ] Error when calling the NLQ model', {
        error: err,
        enabled: AI_ENABLED,
        type: AI_TYPE,
        endpoint: AI_ENDPOINT,
        model: AI_MODEL,
        version: AI_VERSION,
        azure_instance: AI_AZURE_INSTANCE,
        azure_deployment: AI_AZURE_DEPLOYMENT,
        promptValue
      });
    }
    throw UnknownError(`Error when calling the NLQ model [${errorType}]`, { cause: err, promptValue, errorType, errorMessage, errorStatus });
  }
};

// --- Proactive AI startup check (only if enabled) ---
async function proactiveAIStartupCheck() {
  if (AI_ENABLED) {
    logApp.info('[AI] Proactive startup check: AI is enabled, initializing AI clients...');
    try {
      await initializeAIClients();
      logApp.info('[AI] Proactive startup check: AI clients initialized successfully.');
    } catch (err) {
      logApp.error('[AI] Proactive startup check: Failed to initialize AI clients.', {
        error: err,
        enabled: AI_ENABLED,
        type: AI_TYPE,
        endpoint: AI_ENDPOINT,
        model: AI_MODEL,
        version: AI_VERSION,
        azure_instance: AI_AZURE_INSTANCE,
        azure_deployment: AI_AZURE_DEPLOYMENT,
      });
    }
  } else {
    logApp.info('[AI] Proactive startup check: AI is disabled, skipping AI client initialization.');
  }
}

// Run proactive AI startup check at module load
proactiveAIStartupCheck().catch((err) => {
  logApp.error('[AI] Unhandled error in proactiveAIStartupCheck', { error: err });
});
