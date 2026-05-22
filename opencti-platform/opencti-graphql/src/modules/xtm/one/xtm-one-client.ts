import conf, { logApp } from '../../../config/conf';
import { issueXtmJwt } from '../../../domain/xtm-auth';
import type { AuthContext } from '../../../types/user';
import { getHttpClient } from '../../../utils/http-client';

const XTM_ONE_URL = conf.get('xtm:xtm_one_url');
const XTM_ONE_TOKEN = conf.get('xtm:xtm_one_token');

// ── Intent catalog types ────────────────────────────────────────────────

export interface IntentCatalogAgent {
  agent_id: string;
  agent_name: string;
  agent_slug: string | null;
  agent_description: string | null;
  priority: number;
}

export interface IntentCatalogEntry {
  intent: string;
  description: string | null;
  agents: IntentCatalogAgent[];
}

export interface IntentInput {
  name: string;
  description?: string;
}

// ── Registration types ──────────────────────────────────────────────────

export interface XtmOneRegistrationInput {
  platform_identifier: string;
  platform_url: string;
  platform_title: string;
  platform_version: string;
  platform_id: string;
  enterprise_license_pem: string | undefined;
  license_type: string | undefined;
  business_vertical: string;
  intents: IntentInput[];
}

export interface XtmOneRegistrationResponse {
  status: string;
  version: string;
  platform_identifier: string;
  ee_enabled: boolean;
  user_integrations: number;
  chat_web_token: string | null;
  intent_catalog: IntentCatalogEntry[];
}

// ── Client ──────────────────────────────────────────────────────────────

const xtmOneClient = {
  isConfigured: (): boolean => {
    return !!(XTM_ONE_URL && XTM_ONE_TOKEN);
  },

  listAgentsForIntent: async (context: AuthContext, intent: string): Promise<IntentCatalogAgent[]> => {
    if (!XTM_ONE_URL || !XTM_ONE_TOKEN || !context.user) {
      return [];
    }
    try {
      const jwt = await issueXtmJwt(context.user, XTM_ONE_URL);
      const httpClient = getHttpClient({
        baseURL: XTM_ONE_URL,
        responseType: 'json',
        headers: {
          Authorization: `Bearer ${jwt}`,
          'Content-Type': 'application/json',
        },
      });
      const response = await httpClient.get('/api/v1/intents/catalog?vertical=cti&intent=' + encodeURIComponent(intent), { timeout: 15000 });
      return response.data.flatMap((entry: IntentCatalogEntry) => entry.agents);
    } catch (error: any) {
      logApp.error('[XTM One] listAgentsForIntent failed', { error: error.message });
      return [];
    }
  },

  register: async (input: XtmOneRegistrationInput): Promise<XtmOneRegistrationResponse | null> => {
    if (!XTM_ONE_URL || !XTM_ONE_TOKEN) {
      return null;
    }
    try {
      const httpClient = getHttpClient({
        baseURL: XTM_ONE_URL,
        responseType: 'json',
        headers: {
          Authorization: `Bearer ${XTM_ONE_TOKEN}`,
          'Content-Type': 'application/json',
        },
      });
      const response = await httpClient.post('/api/v1/platform/register', input, { timeout: 15000 });
      return response.data;
    } catch (error: any) {
      logApp.error('[XTM One] Registration failed', { error: error.message });
      return null;
    }
  },
};

export default xtmOneClient;
