import { isNotEmptyField } from '../database/utils';
import type { AuthUser } from '../types/user';
import type { BasicStoreSettings } from '../types/settings';
import { isUserHasCapability, SETTINGS_SETMANAGEXTMHUB } from './access';

export interface InputSettingsData { key: string; value: unknown[] }

// The XTM Hub platform token authenticates this platform to XTM Hub: only the users who manage the XTM Hub
// registration can read it. Everyone else gets null, not an error, because the settings every user loads ask for it.
export const readXtmHubTokenFor = (user: AuthUser | undefined, settings: Pick<BasicStoreSettings, 'xtm_hub_token'>): string | null => {
  if (!user || !isUserHasCapability(user, SETTINGS_SETMANAGEXTMHUB)) {
    return null;
  }
  return settings.xtm_hub_token ?? null;
};

const readFirstValue = (item: InputSettingsData | undefined): unknown => {
  if (!item || item.value === undefined || item.value === null) return undefined;
  if (Array.isArray(item.value)) return item.value[0];
  return item.value;
};

export const completeXTMHubDataForRegistration = (user: AuthUser, input: InputSettingsData[]) => {
  const tokenItem = input.find((item) => item.key === 'xtm_hub_token');
  if (!tokenItem) {
    return input;
  }
  // Writing the token ends or replaces the registration: the organization known from the
  // previous one no longer applies. The next connectivity check fetches the new one.
  const completedInput: InputSettingsData[] = input.some((item) => item.key === 'xtm_hub_organization_name')
    ? input
    : [...input, { key: 'xtm_hub_organization_name', value: [] }];
  const statusItem = input.find((item) => item.key === 'xtm_hub_registration_status');
  // Only enrich during an actual registration (non-empty token + status === 'registered').
  // Unregistration sends the same two keys with empty / 'unregistered' values and must NOT
  // re-stamp the registration user / dates as if we were registering.
  const tokenValue = readFirstValue(tokenItem);
  const statusValue = readFirstValue(statusItem);
  if (isNotEmptyField(tokenValue) && statusValue === 'registered') {
    return [
      ...completedInput,
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

  return completedInput;
};
