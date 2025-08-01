import { describe, expect, it } from 'vitest';
import { ADMIN_USER } from '../../utils/testQuery';
import { completeXTMHubDataForEnrollment, type InputSettingsData } from '../../../src/utils/settings.helper';

describe('XTM Hub settings helper', () => {
  it('should complete XTM Data', () => {
    const mockInput: InputSettingsData[] = [
      {
        key: 'xtm_hub_token',
        value: ['d0e2a7ac-288b-4f46-bb45-c4557893ff47']
      },
      { key: 'xtm_hub_enrollment_status', value: ['enrolled'] },
      { key: 'normal_setting', value: ['keep'] },
    ];

    const data = completeXTMHubDataForEnrollment(ADMIN_USER, mockInput);
    const xtmHubToken = data.find((item) => item.key === 'xtm_hub_token');
    const enrollmentStatus = data.find((item) => item.key === 'xtm_hub_enrollment_status');
    const userId = data.find((item) => item.key === 'xtm_hub_enrollment_user_id');
    const userName = data.find((item) => item.key === 'xtm_hub_enrollment_user_name');
    const enrollmentDate = data.find((item) => item.key === 'xtm_hub_enrollment_date');
    const lastConnectivityCheck = data.find((item) => item.key === 'xtm_hub_last_connectivity_check');
    expect(data.length).toEqual(7);
    expect(xtmHubToken).toBeTruthy();
    expect(enrollmentStatus).toBeTruthy();
    expect(userId).toBeTruthy();
    expect(userId?.value).toEqual([ADMIN_USER.id]);
    expect(userName).toBeTruthy();
    expect(userName?.value).toEqual([ADMIN_USER.name]);
    expect(enrollmentDate).toBeTruthy();
    expect(lastConnectivityCheck).toBeTruthy();
  });
  it('should not complete XTM Data', () => {
    const mockInput: InputSettingsData[] = [
      { key: 'normal_setting', value: ['keep'] },
      { key: 'other_setting', value: ['keep'] },
    ];

    const data = completeXTMHubDataForEnrollment(ADMIN_USER, mockInput);
    expect(data.length).toEqual(2);
  });
});
