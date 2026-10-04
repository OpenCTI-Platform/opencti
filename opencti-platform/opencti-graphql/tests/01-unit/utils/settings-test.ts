import { describe, expect, it } from 'vitest';
import { ADMIN_USER } from '../../utils/testQuery';
import { completeXTMHubDataForRegistration, type InputSettingsData, resolveAIEndpointType } from '../../../src/utils/settings.helper';

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
    expect(data.length).toEqual(mockInput.length);
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
    expect(data.length).toEqual(2);
  });
});

describe('AI endpoint type', () => {
  it('should recognize the Filigran domain and its subdomains only', () => {
    expect(resolveAIEndpointType(undefined)).toEqual('');
    expect(resolveAIEndpointType('')).toEqual('');
    expect(resolveAIEndpointType('https://filigran.io/v1')).toEqual('Filigran');
    expect(resolveAIEndpointType('https://ai.Filigran.io:8443/v1')).toEqual('Filigran');
    expect(resolveAIEndpointType('ai.filigran.io/v1')).toEqual('Filigran');
    expect(resolveAIEndpointType('https://filigran.io.example.com/v1')).toEqual('Custom');
    expect(resolveAIEndpointType('https://example.com/filigran.io')).toEqual('Custom');
    expect(resolveAIEndpointType('https://notfiligran.io')).toEqual('Custom');
    expect(resolveAIEndpointType('http://[::1')).toEqual('Custom');
  });
});
