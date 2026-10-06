import { beforeEach, describe, expect, it, vi } from 'vitest';
import { XtmHubRegistrationStatus } from '../../../src/generated/graphql';

// Mock dependencies before importing the module under test
vi.mock('../../../src/domain/xtm-hub', () => ({
  autoRegisterOpenCTIOnStartup: vi.fn(),
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
  logApp: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  },
}));

vi.mock('../../../src/manager/managerModule', () => ({
  registerManager: vi.fn(),
}));

vi.mock('../../../src/modules/xtm/hub/news-feed/news-feed-domain', () => ({
  cleanOldNewsFeedItems: vi.fn(),
}));

import { autoRegisterOpenCTIOnStartup, checkXTMHubConnectivity, loadAndSaveLatestNewsFeed } from '../../../src/domain/xtm-hub';
import { autoRegisterOnBoot, hubRegistrationManager } from '../../../src/manager/hubRegistrationManager';
import { cleanOldNewsFeedItems } from '../../../src/modules/xtm/hub/news-feed/news-feed-domain';

const mockAutoRegisterOpenCTIOnStartup = vi.mocked(autoRegisterOpenCTIOnStartup);
const mockCleanOldNewsFeedItems = vi.mocked(cleanOldNewsFeedItems);
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

  it('should call cleanOldNewsFeedItems on every execution', async () => {
    mockCheckXTMHubConnectivity.mockResolvedValue({ status: XtmHubRegistrationStatus.Unregistered });
    mockCleanOldNewsFeedItems.mockResolvedValue(0);

    await hubRegistrationManager();

    expect(mockCleanOldNewsFeedItems).toHaveBeenCalledOnce();
  });

  it('should call startup auto-registration helper when triggered on boot', async () => {
    mockAutoRegisterOpenCTIOnStartup.mockResolvedValue({ success: true });

    await autoRegisterOnBoot('platform-token');

    expect(mockAutoRegisterOpenCTIOnStartup).toHaveBeenCalledOnce();
    expect(mockAutoRegisterOpenCTIOnStartup).toHaveBeenCalledWith(
      {},
      { id: 'hub-manager-user' },
      'platform-token',
    );
  });

  it('should not throw if startup auto-registration helper fails', async () => {
    mockAutoRegisterOpenCTIOnStartup.mockRejectedValue(new Error('boot registration failed'));

    await expect(autoRegisterOnBoot('platform-token')).resolves.toBeUndefined();
  });
});
