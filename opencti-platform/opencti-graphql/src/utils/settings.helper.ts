import { isNotEmptyField } from '../database/utils';
import type { AuthUser } from '../types/user';

export interface InputSettingsData { key: string; value: [unknown] }

const readFirstValue = (item: InputSettingsData | undefined): unknown => {
  if (!item || item.value === undefined || item.value === null) return undefined;
  if (Array.isArray(item.value)) return item.value[0];
  return item.value;
};

export const completeXTMHubDataForRegistration = (user: AuthUser, input: InputSettingsData[]) => {
  const tokenItem = input.find((item) => item.key === 'xtm_hub_token');
  const statusItem = input.find((item) => item.key === 'xtm_hub_registration_status');
  // Only enrich during an actual registration (non-empty token + status === 'registered').
  // Unregistration sends the same two keys with empty / 'unregistered' values and must NOT
  // re-stamp the registration user / dates as if we were registering.
  const tokenValue = readFirstValue(tokenItem);
  const statusValue = readFirstValue(statusItem);
  if (isNotEmptyField(tokenValue) && statusValue === 'registered') {
    return [
      ...input,
      {
        key: 'xtm_hub_registration_user_id',
        value: [user.id],
      },
      {
        key: 'xtm_hub_registration_user_name',
        value: [user.name],
      },
      {
        key: 'xtm_hub_registration_date',
        value: [new Date()],
      },
      {
        key: 'xtm_hub_last_connectivity_check',
        value: [new Date()],
      },
      {
        key: 'xtm_hub_should_send_connectivity_email',
        value: [true],
      },
    ];
  }

  return input;
};

const FILIGRAN_AI_DOMAIN = 'filigran.io';

// The endpoint host must be filigran.io or one of its subdomains: a substring match would accept any host.
export const resolveAIEndpointType = (endpoint: string | null | undefined): string => {
  if (!isNotEmptyField(endpoint)) {
    return '';
  }
  const value = String(endpoint).trim();
  let hostname: string;
  try {
    hostname = new URL(value.includes('://') ? value : `https://${value}`).hostname.toLowerCase();
  } catch {
    return 'Custom';
  }
  return hostname === FILIGRAN_AI_DOMAIN || hostname.endsWith(`.${FILIGRAN_AI_DOMAIN}`) ? 'Filigran' : 'Custom';
};
