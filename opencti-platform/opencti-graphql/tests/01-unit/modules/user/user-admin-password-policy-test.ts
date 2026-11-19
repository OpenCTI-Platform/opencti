import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import conf, { logApp } from '../../../../src/config/conf';
import { createEntity, patchAttribute } from '../../../../src/database/middleware';
import { storeLoadById } from '../../../../src/database/middleware-loader';
import { elLoadBy } from '../../../../src/database/engine';
import { getEntityFromCache } from '../../../../src/database/cache';
import {
  ADMIN_PASSWORD_POLICY_MISMATCH_REASON,
  adminPasswordPolicyFailedRules,
  checkAdminPasswordPolicy,
  checkPolicyAcceptsAdminPassword,
  initializeAdminUser,
} from '../../../../src/modules/user/user-domain';
import { testContext } from '../../../utils/testQuery';

// Distinctive, so that the tests can check it never leaks into the logs or the error
const WEAK_PASSWORD = 'weak-secret';
const SWITCH = 'app:admin:secure_by_default';
const EXTERNALLY_MANAGED = 'app:admin:externally_managed';
const setSwitch = (value: boolean) => conf.set(SWITCH, value);

vi.mock('../../../../src/database/middleware', () => ({
  createEntity: vi.fn(),
  patchAttribute: vi.fn(),
  updateAttribute: vi.fn(),
}));

vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...await importOriginal<object>(),
  storeLoadById: vi.fn(),
}));

vi.mock('../../../../src/database/engine', async (importOriginal) => ({
  ...await importOriginal<object>(),
  elLoadBy: vi.fn(),
}));

vi.mock('../../../../src/database/cache', () => ({
  getEntitiesListFromCache: vi.fn().mockResolvedValue([]),
  getEntitiesMapFromCache: vi.fn().mockResolvedValue(new Map()),
  getEntityFromCache: vi.fn(),
}));

// Policy the admin password does not match: too short, no uppercase char, no digit
const strictPolicy = {
  password_policy_min_length: 15,
  password_policy_min_lowercase: 1,
  password_policy_min_uppercase: 1,
  password_policy_min_numbers: 1,
};

// Whether the password appears in anything passed to the logger or in the error
const containsPassword = (value: unknown) => JSON.stringify(value).includes(WEAK_PASSWORD);

describe('checkAdminPasswordPolicy', () => {
  let warn: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    warn = vi.spyOn(logApp, 'warn').mockImplementation(() => {});
  });

  afterEach(() => {
    conf.clear(SWITCH);
    vi.restoreAllMocks();
  });

  it('should accept a compliant password, switch off', () => {
    // Given
    setSwitch(false);

    // When
    checkAdminPasswordPolicy(testContext, strictPolicy, 'Compliant-Passw0rd');

    // Then
    expect(warn).not.toHaveBeenCalled();
  });

  it('should accept a compliant password, switch on', () => {
    // Given
    setSwitch(true);

    // When / Then
    expect(() => checkAdminPasswordPolicy(testContext, strictPolicy, 'Compliant-Passw0rd')).not.toThrow();
    expect(warn).not.toHaveBeenCalled();
  });

  it('should accept any password when the policy is empty, switch on', () => {
    // Given
    setSwitch(true);

    // When / Then
    expect(() => checkAdminPasswordPolicy(testContext, {}, 'a')).not.toThrow();
    expect(warn).not.toHaveBeenCalled();
  });

  it('should warn with the failed rules for a non-compliant password, switch off', () => {
    // Given
    setSwitch(false);

    // When
    checkAdminPasswordPolicy(testContext, strictPolicy, WEAK_PASSWORD);

    // Then
    expect(warn).toHaveBeenCalledTimes(1);
    expect(warn).toHaveBeenCalledWith(expect.stringContaining('app:admin:secure_by_default=false'), {
      failed_rules: ['size must be >= 15', 'number of digits must be >= 1', 'number of upper chars must be >= 1'],
    });
    expect(containsPassword(warn.mock.calls)).toBe(false);
  });

  it('should refuse a non-compliant password, switch on', () => {
    // Given
    setSwitch(true);

    // When
    let error: any;
    try {
      checkAdminPasswordPolicy(testContext, strictPolicy, WEAK_PASSWORD);
    } catch (e) {
      error = e;
    }

    // Then
    expect(error.extensions.code).toBe('CONFIGURATION_ERROR');
    expect(error.extensions.data.failed_rules).toEqual(['size must be >= 15', 'number of digits must be >= 1', 'number of upper chars must be >= 1']);
    expect(containsPassword({ message: error.message, extensions: error.extensions })).toBe(false);
    expect(warn).not.toHaveBeenCalled();
  });
});

describe('initializeAdminUser', () => {
  // Stops the admin creation right after the password policy step of addUser
  const CREATION_REACHED = 'admin creation reached';
  let warn: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    vi.clearAllMocks();
    warn = vi.spyOn(logApp, 'warn').mockImplementation(() => {});
    vi.mocked(getEntityFromCache).mockResolvedValue(strictPolicy as never);
    vi.mocked(elLoadBy).mockResolvedValue(undefined as never);
    vi.mocked(createEntity).mockRejectedValue(new Error(CREATION_REACHED));
  });

  afterEach(() => {
    conf.clear(SWITCH);
    conf.clear(EXTERNALLY_MANAGED);
    vi.restoreAllMocks();
  });

  it('should refuse to start before updating the admin when its password does not match the policy, switch on', async () => {
    // Given
    setSwitch(true);

    // When / Then
    await expect(initializeAdminUser(testContext)).rejects.toThrow('does not match the local password policy');
    expect(storeLoadById).not.toHaveBeenCalled();
    expect(patchAttribute).not.toHaveBeenCalled();
    expect(createEntity).not.toHaveBeenCalled();
  });

  it('should warn and still create the admin of a new platform when its password does not match the policy, switch off', async () => {
    // Given
    setSwitch(false);
    vi.mocked(storeLoadById).mockResolvedValue(undefined as never);

    // When / Then: addUser does not apply the password policy a second time
    await expect(initializeAdminUser(testContext)).rejects.toThrow(CREATION_REACHED);
    expect(warn).toHaveBeenCalledWith(expect.stringContaining('app:admin:secure_by_default=false'), expect.anything());
    expect(createEntity).toHaveBeenCalledTimes(1);
    // The check and the password validity of the created account
    expect(getEntityFromCache).toHaveBeenCalledTimes(2);
  });

  it('should skip the check when the admin is externally managed, switch on', async () => {
    // Given
    setSwitch(true);
    conf.set(EXTERNALLY_MANAGED, true);
    vi.mocked(storeLoadById).mockResolvedValue(undefined as never);

    // When / Then: the settings are read once, for the password validity of the created account, and not for the check
    await expect(initializeAdminUser(testContext)).rejects.toThrow(CREATION_REACHED);
    expect(getEntityFromCache).toHaveBeenCalledTimes(1);
    expect(warn).not.toHaveBeenCalled();
    expect(createEntity).toHaveBeenCalledWith(expect.anything(), expect.anything(), expect.objectContaining({ account_status: 'Locked' }), 'User', { complete: true });
  });
});

describe('checkPolicyAcceptsAdminPassword', () => {
  // A policy that no configured admin password matches
  const unreachablePolicy = { password_policy_min_length: 200 };

  afterEach(() => {
    conf.clear(SWITCH);
    conf.clear(EXTERNALLY_MANAGED);
  });

  it('should accept any policy, switch off', () => {
    // Given
    setSwitch(false);

    // When / Then
    expect(adminPasswordPolicyFailedRules(testContext, unreachablePolicy)).toEqual([]);
    expect(() => checkPolicyAcceptsAdminPassword(testContext, unreachablePolicy)).not.toThrow();
  });

  it('should accept any policy when the admin is externally managed, switch on', () => {
    // Given
    setSwitch(true);
    conf.set(EXTERNALLY_MANAGED, true);

    // When / Then
    expect(adminPasswordPolicyFailedRules(testContext, unreachablePolicy)).toEqual([]);
    expect(() => checkPolicyAcceptsAdminPassword(testContext, unreachablePolicy)).not.toThrow();
  });

  it('should accept a policy the admin password matches, switch on', () => {
    // Given
    setSwitch(true);

    // When / Then
    expect(() => checkPolicyAcceptsAdminPassword(testContext, {})).not.toThrow();
  });

  it('should refuse a policy the admin password does not match, switch on', () => {
    // Given
    setSwitch(true);

    // When
    let error: any;
    try {
      checkPolicyAcceptsAdminPassword(testContext, unreachablePolicy);
    } catch (e) {
      error = e;
    }

    // Then
    expect(error.message).toBe(ADMIN_PASSWORD_POLICY_MISMATCH_REASON);
    expect(error.extensions.data.failed_rules).toEqual(['size must be >= 200']);
  });
});
