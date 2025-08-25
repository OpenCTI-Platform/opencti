import type { AuthUser } from '../types/user';

export interface InputSettingsData { key: string, value: [unknown] }

export const completeXTMHubDataForRegistration = (user: AuthUser, input: InputSettingsData[]) => {
  const tokenItem = input.find((item) => item.key === 'xtm_hub_token');
  const statusItem = input.find((item) => item.key === 'xtm_hub_registration_status');
  if (tokenItem?.value && statusItem?.value) {
    return [
      ...input,
      {
        key: 'xtm_hub_registration_user_id',
        value: [user.id]
      },
      {
        key: 'xtm_hub_registration_user_name',
        value: [user.name]
      },
      {
        key: 'xtm_hub_registration_date',
        value: [new Date()]
      },
      {
        key: 'xtm_hub_last_connectivity_check',
        value: [new Date()]
      },
      {
        key: 'xtm_hub_should_send_connectivity_email',
        value: [true]
      }
    ];
  }

  return input;
};
