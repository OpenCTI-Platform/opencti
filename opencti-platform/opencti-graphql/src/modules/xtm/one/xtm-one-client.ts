import axios from 'axios';
import conf, { logApp } from '../../../config/conf';

const XTM_ONE_URL = conf.get('xtm:xtm_one_url');
const XTM_ONE_TOKEN = conf.get('xtm:xtm_one_token');

// ── Intent catalog types ────────────────────────────────────────────────

export interface IntentCatalogAgent {
  agent_id: string;
  agent_name: string;
  agent_slug: string | null;
  agent_description: string | null;
  vertical: string | null;
  priority: number;
  is_default: boolean;
  is_locked: boolean;
  enabled: boolean;
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

  register: async (input: XtmOneRegistrationInput): Promise<XtmOneRegistrationResponse | null> => {
    if (!XTM_ONE_URL || !XTM_ONE_TOKEN) {
      return null;
    }
    try {
      const url = `${XTM_ONE_URL}/api/v1/platform/register`;
      const response = await axios.post(url, input, {
        headers: {
          Authorization: `Bearer ${XTM_ONE_TOKEN}`,
          'Content-Type': 'application/json',
        },
        timeout: 15000,
      });
      return response.data;
    } catch (error: any) {
      logApp.error('[XTM One] Registration failed', { error: error.message });
      return null;
    }
  },
};

export default xtmOneClient;
