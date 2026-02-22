import axios from 'axios';
import conf from '../../../config/conf';
import { logApp } from '../../../config/conf';

const XTM_ONE_URL = conf.get('xtm:xtm_one_url');
const XTM_ONE_TOKEN = conf.get('xtm:xtm_one_token');

export interface XtmOneUserEntry {
  email: string;
  display_name: string;
  api_key: string;
}

export interface XtmOneRegistrationInput {
  platform_identifier: string;
  platform_url: string;
  platform_title: string;
  platform_version: string;
  platform_id: string;
  enterprise_license_pem: string | undefined;
  users: XtmOneUserEntry[];
}

export interface XtmOneRegistrationResponse {
  status: string;
  platform_identifier: string;
  ee_enabled: boolean;
  user_integrations: number;
}

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
