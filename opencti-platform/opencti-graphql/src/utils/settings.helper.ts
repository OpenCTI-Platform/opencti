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
