import { describe, expect, it } from 'vitest';
import { ADMIN_USER } from '../../utils/testQuery';
import { completeXTMHubDataForRegistration, type InputSettingsData } from '../../../src/utils/settings.helper';

describe('XTM Hub settings helper', () => {
  it('should complete XTM Data', () => {
    const mockInput: InputSettingsData[] = [
      {
        key: 'xtm_hub_token',
        value: ['d0e2a7ac-288b-4f46-bb45-c4557893ff47']
      },
      { key: 'xtm_hub_registration_status', value: ['registered'] },
      { key: 'normal_setting', value: ['keep'] },
    ];

    const data = completeXTMHubDataForRegistration(ADMIN_USER, mockInput);
    const xtmHubToken = data.find((item) => item.key === 'xtm_hub_token');
    const registrationStatus = data.find((item) => item.key === 'xtm_hub_registration_status');
    const userId = data.find((item) => item.key === 'xtm_hub_registration_user_id');
    const userName = data.find((item) => item.key === 'xtm_hub_registration_user_name');
    const registrationDate = data.find((item) => item.key === 'xtm_hub_registration_date');
    const lastConnectivityCheck = data.find((item) => item.key === 'xtm_hub_last_connectivity_check');
    const shouldSendConnectivityEmail = data.find((item) => item.key === 'xtm_hub_should_send_connectivity_email');
    expect(data.length).toEqual(8);
    expect(xtmHubToken).toBeTruthy();
    expect(registrationStatus).toBeTruthy();
    expect(userId).toBeTruthy();
    expect(userId?.value).toEqual([ADMIN_USER.id]);
    expect(userName).toBeTruthy();
    expect(userName?.value).toEqual([ADMIN_USER.name]);
    expect(registrationDate).toBeTruthy();
    expect(lastConnectivityCheck).toBeTruthy();
    expect(shouldSendConnectivityEmail).toBeTruthy();
  });
  it('should not complete XTM Data', () => {
    const mockInput: InputSettingsData[] = [
      { key: 'normal_setting', value: ['keep'] },
      { key: 'other_setting', value: ['keep'] },
    ];

    const data = completeXTMHubDataForRegistration(ADMIN_USER, mockInput);
    expect(data.length).toEqual(2);
  });
});
