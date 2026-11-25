import { describe, expect, it } from 'vitest';
import { ADMIN_USER } from '../../utils/testQuery';
import { completeXTMHubDataForRegistration, type InputSettingsData, readXtmHubTokenFor } from '../../../src/utils/settings.helper';
import type { AuthUser } from '../../../src/types/user';

describe('XTM Hub settings helper', () => {
  it('should complete XTM Data', () => {
    const mockInput: InputSettingsData[] = [
      {
        key: 'xtm_hub_token',
        value: ['d0e2a7ac-288b-4f46-bb45-c4557893ff47'],
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
    const organizationName = data.find((item) => item.key === 'xtm_hub_organization_name');
    expect(data.length).toEqual(9);
    expect(xtmHubToken).toBeTruthy();
    expect(registrationStatus).toBeTruthy();
    expect(userId).toBeTruthy();
    expect(userId?.value).toEqual([ADMIN_USER.id]);
    expect(userName).toBeTruthy();
    expect(userName?.value).toEqual([ADMIN_USER.name]);
    expect(registrationDate).toBeTruthy();
    expect(lastConnectivityCheck).toBeTruthy();
    expect(shouldSendConnectivityEmail).toBeTruthy();
    // A new registration may target another workspace: the previous organization is cleared
    expect(organizationName?.value).toEqual([]);
  });
  it('should not complete XTM Data', () => {
    const mockInput: InputSettingsData[] = [
      { key: 'normal_setting', value: ['keep'] },
      { key: 'other_setting', value: ['keep'] },
    ];

    const data = completeXTMHubDataForRegistration(ADMIN_USER, mockInput);
    expect(data.length).toEqual(2);
  });
  it('should not complete XTM Data on unregistration (empty token + status unregistered)', () => {
    const mockInput: InputSettingsData[] = [
      { key: 'xtm_hub_token', value: [''] },
      { key: 'xtm_hub_registration_status', value: ['unregistered'] },
      { key: 'xtm_hub_registration_user_id', value: [''] },
      { key: 'xtm_hub_registration_user_name', value: [''] },
      { key: 'xtm_hub_registration_date', value: [''] },
      { key: 'xtm_hub_last_connectivity_check', value: [''] },
    ];

    const data = completeXTMHubDataForRegistration(ADMIN_USER, mockInput);
    expect(data.length).toEqual(mockInput.length + 1);
    expect(data.find((item) => item.key === 'xtm_hub_organization_name')?.value).toEqual([]);
    expect(data.find((item) => item.key === 'xtm_hub_registration_user_id')?.value).toEqual(['']);
    expect(data.find((item) => item.key === 'xtm_hub_registration_user_name')?.value).toEqual(['']);
    expect(data.find((item) => item.key === 'xtm_hub_registration_date')?.value).toEqual(['']);
    expect(data.find((item) => item.key === 'xtm_hub_last_connectivity_check')?.value).toEqual(['']);
    expect(data.find((item) => item.key === 'xtm_hub_should_send_connectivity_email')).toBeUndefined();
  });
  it('should not complete XTM Data when token is empty even if status is registered', () => {
    const mockInput: InputSettingsData[] = [
      { key: 'xtm_hub_token', value: [''] },
      { key: 'xtm_hub_registration_status', value: ['registered'] },
    ];

    const data = completeXTMHubDataForRegistration(ADMIN_USER, mockInput);
    expect(data.length).toEqual(3);
    expect(data.find((item) => item.key === 'xtm_hub_organization_name')?.value).toEqual([]);
  });
  it('should keep an organization name explicitly given with the token', () => {
    const mockInput: InputSettingsData[] = [
      { key: 'xtm_hub_token', value: ['d0e2a7ac-288b-4f46-bb45-c4557893ff47'] },
      { key: 'xtm_hub_organization_name', value: ['Filigran'] },
    ];

    const data = completeXTMHubDataForRegistration(ADMIN_USER, mockInput);
    expect(data).toEqual(mockInput);
  });
});

describe('XTM Hub token visibility', () => {
  const settings = { xtm_hub_token: 'platform-token' };
  const userWith = (capabilities: string[]) => ({ ...ADMIN_USER, capabilities: capabilities.map((name) => ({ name })) }) as AuthUser;

  it('should give the token to a user who manages the XTM Hub registration', () => {
    expect(readXtmHubTokenFor(userWith(['SETTINGS_SETMANAGEXTMHUB']), settings)).toEqual('platform-token');
  });
  it('should give the token to a user with the BYPASS capability', () => {
    expect(readXtmHubTokenFor(ADMIN_USER, settings)).toEqual('platform-token');
  });
  it('should hide the token from a user who does not manage the XTM Hub registration', () => {
    expect(readXtmHubTokenFor(userWith([]), settings)).toBeNull();
    expect(readXtmHubTokenFor(userWith(['KNOWLEDGE', 'SETTINGS_SETPARAMETERS', 'SETTINGS_SETACCESSES']), settings)).toBeNull();
  });
  it('should hide the token when there is no user', () => {
    expect(readXtmHubTokenFor(undefined, settings)).toBeNull();
  });
  it('should give null when the platform is not registered', () => {
    expect(readXtmHubTokenFor(ADMIN_USER, {})).toBeNull();
  });
});
