import { beforeEach, describe, expect, it, vi } from 'vitest';
import { XtmHubRegistrationStatus } from '../../../src/generated/graphql';

// Mock dependencies before importing the module under test
vi.mock('../../../src/domain/xtm-hub', () => ({
  checkXTMHubConnectivity: vi.fn(),
  loadAndSaveLatestNewsFeed: vi.fn(),
}));

vi.mock('../../../src/utils/access', () => ({
  executionContext: vi.fn().mockReturnValue({}),
  HUB_REGISTRATION_MANAGER_USER: { id: 'hub-manager-user' },
}));

vi.mock('../../../src/config/conf', () => ({
  default: { get: vi.fn().mockReturnValue(undefined) },
  booleanConf: vi.fn().mockReturnValue(true),
}));

vi.mock('../../../src/manager/managerModule', () => ({
  registerManager: vi.fn(),
}));

import { hubRegistrationManager } from '../../../src/manager/hubRegistrationManager';
import { checkXTMHubConnectivity, loadAndSaveLatestNewsFeed } from '../../../src/domain/xtm-hub';

const mockCheckXTMHubConnectivity = vi.mocked(checkXTMHubConnectivity);
const mockLoadAndSaveLatestNewsFeed = vi.mocked(loadAndSaveLatestNewsFeed);

describe('hubRegistrationManager', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should call checkXTMHubConnectivity on every execution', async () => {
    mockCheckXTMHubConnectivity.mockResolvedValue({ status: XtmHubRegistrationStatus.Unregistered });

    await hubRegistrationManager();

    expect(mockCheckXTMHubConnectivity).toHaveBeenCalledOnce();
  });

  it('should load and save the news feed when platform is registered', async () => {
    mockCheckXTMHubConnectivity.mockResolvedValue({ status: XtmHubRegistrationStatus.Registered });
    mockLoadAndSaveLatestNewsFeed.mockResolvedValue(undefined);

    await hubRegistrationManager();

    expect(mockLoadAndSaveLatestNewsFeed).toHaveBeenCalledOnce();
  });

  it('should NOT load and save the news feed when platform is unregistered', async () => {
    mockCheckXTMHubConnectivity.mockResolvedValue({ status: XtmHubRegistrationStatus.Unregistered });

    await hubRegistrationManager();

    expect(mockLoadAndSaveLatestNewsFeed).not.toHaveBeenCalled();
  });

  it('should NOT load and save the news feed when platform has lost connectivity', async () => {
    mockCheckXTMHubConnectivity.mockResolvedValue({ status: XtmHubRegistrationStatus.LostConnectivity });

    await hubRegistrationManager();

    expect(mockLoadAndSaveLatestNewsFeed).not.toHaveBeenCalled();
  });

  it('should propagate errors thrown by checkXTMHubConnectivity', async () => {
    const error = new Error('Hub connectivity check failed');
    mockCheckXTMHubConnectivity.mockRejectedValue(error);

    await expect(hubRegistrationManager()).rejects.toThrow('Hub connectivity check failed');
    expect(mockLoadAndSaveLatestNewsFeed).not.toHaveBeenCalled();
  });

  it('should propagate errors thrown by loadAndSaveLatestNewsFeed when registered', async () => {
    mockCheckXTMHubConnectivity.mockResolvedValue({ status: XtmHubRegistrationStatus.Registered });
    const error = new Error('Failed to load news feed');
    mockLoadAndSaveLatestNewsFeed.mockRejectedValue(error);

    await expect(hubRegistrationManager()).rejects.toThrow('Failed to load news feed');
  });
});
