import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';
import ipWhitelistMiddleware, { ipMatchesWhitelist, isUserExcluded, isLoginOnlyRequest, checkIpWhitelistForRequest } from '../../../src/http/ipWhitelistMiddleware';
import * as cache from '../../../src/database/cache';
import * as userDomain from '../../../src/domain/user';
import * as listener from '../../../src/listener/UserActionListener';
import { logApp } from '../../../src/config/conf';

vi.mock('../../../src/database/cache', () => ({
  getEntityFromCache: vi.fn(),
  getEntitiesMapFromCache: vi.fn(),
}));

vi.mock('../../../src/domain/user', () => ({
  authenticateUserFromRequest: vi.fn(),
  userWithOrigin: vi.fn((req, user) => user),
}));

vi.mock('../../../src/listener/UserActionListener', () => ({
  publishUserAction: vi.fn(),
}));

vi.mock('../../../src/config/conf', async (importOriginal: any) => {
  const actual = await importOriginal();
  return {
    ...actual,
    default: {
      ...actual.default,
      get: vi.fn((key) => {
        if (key === 'app:ip_whitelist_enabled') return true;
        return actual.default.get(key);
      }),
    },
    logApp: {
      ...actual.logApp,
      warn: vi.fn(),
      error: vi.fn(),
    },
  };
});

vi.mock('../../../src/utils/access', () => ({
  executionContext: vi.fn().mockReturnValue('mock-context'),
  SYSTEM_USER: { id: 'system-user' },
}));

// ─── ipMatchesWhitelist ─────────────────────────────────────────────────────

describe('ipMatchesWhitelist', () => {
  describe('exact IPv4 matching', () => {
    it('should match an exact IPv4 address', () => {
      expect(ipMatchesWhitelist('192.168.1.1', ['192.168.1.1'])).toBe(true);
    });

    it('should not match a different IPv4 address', () => {
      expect(ipMatchesWhitelist('192.168.1.2', ['192.168.1.1'])).toBe(false);
    });

    it('should match when IP is one of multiple entries', () => {
      expect(ipMatchesWhitelist('10.0.0.5', ['192.168.1.1', '10.0.0.5', '172.16.0.1'])).toBe(true);
    });
  });

  describe('CIDR IPv4 matching', () => {
    it('should match an IP within a /24 subnet', () => {
      expect(ipMatchesWhitelist('192.168.1.100', ['192.168.1.0/24'])).toBe(true);
    });

    it('should not match an IP outside a /24 subnet', () => {
      expect(ipMatchesWhitelist('192.168.2.1', ['192.168.1.0/24'])).toBe(false);
    });

    it('should match an IP within a /16 subnet', () => {
      expect(ipMatchesWhitelist('10.0.255.1', ['10.0.0.0/16'])).toBe(true);
    });

    it('should not match an IP outside a /16 subnet', () => {
      expect(ipMatchesWhitelist('10.1.0.1', ['10.0.0.0/16'])).toBe(false);
    });

    it('should match a /32 (single host CIDR)', () => {
      expect(ipMatchesWhitelist('1.2.3.4', ['1.2.3.4/32'])).toBe(true);
    });

    it('should not match a different IP against /32', () => {
      expect(ipMatchesWhitelist('1.2.3.5', ['1.2.3.4/32'])).toBe(false);
    });
  });

  describe('IPv6 matching', () => {
    it('should match an exact IPv6 address', () => {
      expect(ipMatchesWhitelist('::1', ['::1'])).toBe(true);
    });

    it('should match IPv6 with full notation vs compressed', () => {
      expect(ipMatchesWhitelist('0000:0000:0000:0000:0000:0000:0000:0001', ['::1'])).toBe(true);
    });

    it('should match an IPv6 within a CIDR range', () => {
      expect(ipMatchesWhitelist('2001:db8::1', ['2001:db8::/32'])).toBe(true);
    });

    it('should not match an IPv6 outside a CIDR range', () => {
      expect(ipMatchesWhitelist('2001:db9::1', ['2001:db8::/32'])).toBe(false);
    });
  });

  describe('IPv4-mapped IPv6 addresses', () => {
    it('should match IPv4-mapped IPv6 against plain IPv4', () => {
      // ipaddr.process normalizes ::ffff:192.168.1.1 to 192.168.1.1
      expect(ipMatchesWhitelist('::ffff:192.168.1.1', ['192.168.1.1'])).toBe(true);
    });

    it('should match IPv4-mapped IPv6 against IPv4 CIDR', () => {
      expect(ipMatchesWhitelist('::ffff:10.0.0.5', ['10.0.0.0/24'])).toBe(true);
    });
  });

  describe('edge cases', () => {
    it('should return false for an empty whitelist', () => {
      expect(ipMatchesWhitelist('192.168.1.1', [])).toBe(false);
    });

    it('should return false for invalid source IP', () => {
      expect(ipMatchesWhitelist('not-an-ip', ['192.168.1.0/24'])).toBe(false);
    });

    it('should skip invalid whitelist entries without crashing', () => {
      expect(ipMatchesWhitelist('192.168.1.1', ['not-valid', '192.168.1.1'])).toBe(true);
    });

    it('should return false when only invalid entries are in whitelist', () => {
      expect(ipMatchesWhitelist('192.168.1.1', ['garbage', 'also/bad'])).toBe(false);
    });

    it('should handle mixed IPv4 and IPv6 entries', () => {
      const whitelist = ['192.168.1.0/24', '2001:db8::/32', '10.0.0.1'];
      expect(ipMatchesWhitelist('192.168.1.50', whitelist)).toBe(true);
      expect(ipMatchesWhitelist('2001:db8::abc', whitelist)).toBe(true);
      expect(ipMatchesWhitelist('10.0.0.1', whitelist)).toBe(true);
      expect(ipMatchesWhitelist('172.16.0.1', whitelist)).toBe(false);
    });
  });
});

// ─── isUserExcluded ─────────────────────────────────────────────────────────

describe('isUserExcluded', () => {
  describe('user ID matching', () => {
    it('should return true when user.id matches an exclusion ID', () => {
      const user = { id: 'user-1', internal_id: 'user-1-int', groups: [], organizations: [] };
      expect(isUserExcluded(user, ['user-1'])).toBe(true);
    });

    it('should return true when user.internal_id matches an exclusion ID', () => {
      const user = { id: 'user-1', internal_id: 'user-1-int', groups: [], organizations: [] };
      expect(isUserExcluded(user, ['user-1-int'])).toBe(true);
    });

    it('should return false when user ID is not in exclusion list', () => {
      const user = { id: 'user-1', internal_id: 'user-1-int', groups: [], organizations: [] };
      expect(isUserExcluded(user, ['user-2', 'user-3'])).toBe(false);
    });
  });

  describe('group ID matching', () => {
    it('should return true when a group internal_id matches', () => {
      const user = {
        id: 'user-1',
        internal_id: 'user-1-int',
        groups: [{ internal_id: 'group-a' }, { internal_id: 'group-b' }],
        organizations: [],
      };
      expect(isUserExcluded(user, ['group-a'])).toBe(true);
    });

    it('should return true when a group id (fallback) matches', () => {
      const user = {
        id: 'user-1',
        internal_id: 'user-1-int',
        groups: [{ id: 'group-a' }], // no internal_id → falls back to id
        organizations: [],
      };
      expect(isUserExcluded(user, ['group-a'])).toBe(true);
    });

    it('should return false when no group matches', () => {
      const user = {
        id: 'user-1',
        internal_id: 'user-1-int',
        groups: [{ internal_id: 'group-x' }],
        organizations: [],
      };
      expect(isUserExcluded(user, ['group-z'])).toBe(false);
    });
  });

  describe('organization ID matching', () => {
    it('should return true when an organization internal_id matches', () => {
      const user = {
        id: 'user-1',
        internal_id: 'user-1-int',
        groups: [],
        organizations: [{ internal_id: 'org-1' }],
      };
      expect(isUserExcluded(user, ['org-1'])).toBe(true);
    });

    it('should return true when an organization id (fallback) matches', () => {
      const user = {
        id: 'user-1',
        internal_id: 'user-1-int',
        groups: [],
        organizations: [{ id: 'org-1' }],
      };
      expect(isUserExcluded(user, ['org-1'])).toBe(true);
    });

    it('should return false when no organization matches', () => {
      const user = {
        id: 'user-1',
        internal_id: 'user-1-int',
        groups: [],
        organizations: [{ internal_id: 'org-other' }],
      };
      expect(isUserExcluded(user, ['org-1'])).toBe(false);
    });
  });

  describe('edge cases', () => {
    it('should return false for null exclusionIds', () => {
      const user = { id: 'user-1', internal_id: 'u1', groups: [], organizations: [] };
      expect(isUserExcluded(user, null)).toBe(false);
    });

    it('should return false for empty exclusionIds', () => {
      const user = { id: 'user-1', internal_id: 'u1', groups: [], organizations: [] };
      expect(isUserExcluded(user, [])).toBe(false);
    });

    it('should return false for null user', () => {
      expect(isUserExcluded(null, ['user-1'])).toBe(false);
    });

    it('should return false for undefined user', () => {
      expect(isUserExcluded(undefined, ['user-1'])).toBe(false);
    });

    it('should handle user with no groups or organizations fields', () => {
      const user = { id: 'user-1', internal_id: 'u1' };
      // groups/orgs are undefined — should not crash
      expect(isUserExcluded(user, ['some-group'])).toBe(false);
    });

    it('should match via multiple vectors simultaneously', () => {
      const user = {
        id: 'user-1',
        internal_id: 'user-1-int',
        groups: [{ internal_id: 'group-a' }],
        organizations: [{ internal_id: 'org-1' }],
      };
      // Matches via org
      expect(isUserExcluded(user, ['org-1'])).toBe(true);
      // Matches via group
      expect(isUserExcluded(user, ['group-a'])).toBe(true);
      // Matches via user id
      expect(isUserExcluded(user, ['user-1'])).toBe(true);
    });
  });
});

// ─── isLoginOnlyRequest ─────────────────────────────────────────────────────

describe('isLoginOnlyRequest', () => {
  const makeReq = (query: string) => ({ body: { query } });

  describe('allowed login queries', () => {
    it('should allow publicSettings query', () => {
      const req = makeReq('query publicSettings { publicSettings { platform_title } }');
      expect(isLoginOnlyRequest(req)).toBe(true);
    });

    it('should allow publicSettings with any operation name (e.g. LoginRootPublicQuery)', () => {
      const req = makeReq(`query LoginRootPublicQuery {
        publicSettings {
          platform_title
          platform_providers { name type provider }
        }
      }`);
      expect(isLoginOnlyRequest(req)).toBe(true);
    });

    it('should allow token mutation', () => {
      const req = makeReq('mutation TokenMutation { token(input: { email: "a@b.com", password: "x" }) }');
      expect(isLoginOnlyRequest(req)).toBe(true);
    });

    it('should allow otpLogin mutation', () => {
      const req = makeReq('mutation OtpLogin { otpLogin(input: { code: "123456" }) }');
      expect(isLoginOnlyRequest(req)).toBe(true);
    });

    it('should allow otpGeneration query', () => {
      const req = makeReq('query OtpGen { otpGeneration { secret uri } }');
      expect(isLoginOnlyRequest(req)).toBe(true);
    });

    it('should allow otpValidation mutation', () => {
      const req = makeReq('mutation OtpVal { otpValidation(input: { code: "123456" }) }');
      expect(isLoginOnlyRequest(req)).toBe(true);
    });

    it('should allow publicSettings with fragments', () => {
      const req = makeReq(`query LoginRootPublicQuery {
        publicSettings {
          platform_title
          ...ExternalAuthsFragment
        }
      }
      fragment ExternalAuthsFragment on PublicSettings {
        platform_providers { name type }
      }`);
      expect(isLoginOnlyRequest(req)).toBe(true);
    });
  });

  describe('blocked queries', () => {
    it('should block me query', () => {
      const req = makeReq('query MeQuery { me { id name user_email } }');
      expect(isLoginOnlyRequest(req)).toBe(false);
    });

    it('should block mixed query (publicSettings + me)', () => {
      const req = makeReq('query Mixed { publicSettings { platform_title } me { id } }');
      expect(isLoginOnlyRequest(req)).toBe(false);
    });

    it('should block query with allowed name but disallowed field', () => {
      const req = makeReq('query publicSettings { users { edges { node { id } } } }');
      expect(isLoginOnlyRequest(req)).toBe(false);
    });

    it('should block anonymous query with disallowed field', () => {
      const req = makeReq('{ me { id } }');
      expect(isLoginOnlyRequest(req)).toBe(false);
    });

    it('should block publicDashboardByUriKey query', () => {
      const req = makeReq('query Dashboard { publicDashboardByUriKey(uri_key: "test") { id } }');
      expect(isLoginOnlyRequest(req)).toBe(false);
    });

    it('should block when query field is spoofed as operationName', () => {
      // Attacker sends operationName: publicSettings but queries something else
      const req = { body: { operationName: 'publicSettings', query: '{ me { id } }' } };
      expect(isLoginOnlyRequest(req)).toBe(false);
    });
  });

  describe('edge cases', () => {
    it('should return false for missing query', () => {
      expect(isLoginOnlyRequest({ body: {} })).toBeFalsy();
    });

    it('should return false for invalid query string', () => {
      expect(isLoginOnlyRequest({ body: { query: 'not valid graphql {{{' } })).toBe(false);
    });

    it('should return false for empty query', () => {
      expect(isLoginOnlyRequest({ body: { query: '' } })).toBeFalsy();
    });

    it('should handle batched requests - all allowed', () => {
      const req = {
        body: [
          { query: 'query A { publicSettings { platform_title } }' },
          { query: 'mutation B { token(input: { email: "a@b.com", password: "x" }) }' },
        ],
      };
      expect(isLoginOnlyRequest(req)).toBe(true);
    });

    it('should handle batched requests - one disallowed', () => {
      const req = {
        body: [
          { query: 'query A { publicSettings { platform_title } }' },
          { query: 'query B { me { id } }' },
        ],
      };
      expect(isLoginOnlyRequest(req)).toBe(false);
    });
  });
});

// ─── ipWhitelistMiddleware ──────────────────────────────────────────────────

describe('ipWhitelistMiddleware', () => {
  let req: any;
  let res: any;
  let next: any;

  beforeEach(() => {
    vi.clearAllMocks();
    req = { ip: '192.168.1.50', body: {} };
    res = { status: vi.fn().mockReturnThis(), json: vi.fn() };
    next = vi.fn();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('should call next if no source IP is present', async () => {
    req.ip = undefined;
    await ipWhitelistMiddleware(req, res, next);
    expect(next).toHaveBeenCalled();
  });

  it('should call next if whitelist is disabled in settings', async () => {
    vi.mocked(cache.getEntityFromCache as any).mockResolvedValueOnce({
      platform_ip_whitelist_enabled: false,
    });
    await ipWhitelistMiddleware(req, res, next);
    expect(next).toHaveBeenCalled();
  });

  it('should call next if whitelist is empty', async () => {
    vi.mocked(cache.getEntityFromCache as any).mockResolvedValueOnce({
      platform_ip_whitelist_enabled: true,
      platform_ip_whitelist: [],
    });
    await ipWhitelistMiddleware(req, res, next);
    expect(next).toHaveBeenCalled();
  });

  it('should call next if IP matches the whitelist', async () => {
    vi.mocked(cache.getEntityFromCache as any).mockResolvedValueOnce({
      platform_ip_whitelist_enabled: true,
      platform_ip_whitelist: ['192.168.1.0/24'],
    });
    await ipWhitelistMiddleware(req, res, next);
    expect(next).toHaveBeenCalled();
  });

  it('should allow unauthenticated login requests when not in whitelist', async () => {
    vi.mocked(cache.getEntityFromCache as any).mockResolvedValueOnce({
      platform_ip_whitelist_enabled: true,
      platform_ip_whitelist: ['10.0.0.0/8'],
    });
    vi.mocked(userDomain.authenticateUserFromRequest as any).mockResolvedValueOnce(null);
    req.body = { query: 'query { publicSettings { platform_title } }' };

    await ipWhitelistMiddleware(req, res, next);
    expect(next).toHaveBeenCalled();
  });

  it('should block unauthenticated requests and log rejection (throttled)', async () => {
    vi.useFakeTimers();
    vi.mocked(cache.getEntityFromCache as any).mockResolvedValue({
      platform_ip_whitelist_enabled: true,
      platform_ip_whitelist: ['10.0.0.0/8'],
    });
    vi.mocked(userDomain.authenticateUserFromRequest as any).mockResolvedValue(null);
    req.body = { query: 'query { me { id } }' }; // Not a login query
    req.ip = '203.0.113.1';

    // First request should block and log
    await ipWhitelistMiddleware(req, res, next);
    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(200);
    expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ errors: expect.any(Array) }));
    expect(logApp.warn).toHaveBeenCalledTimes(1);
    expect(listener.publishUserAction).toHaveBeenCalledTimes(1);

    // Second request within window should block but NOT log
    vi.clearAllMocks();
    await ipWhitelistMiddleware(req, res, next);
    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(200);
    expect(logApp.warn).not.toHaveBeenCalled();
    expect(listener.publishUserAction).not.toHaveBeenCalled();

    // Advance time past the 60s window
    vi.advanceTimersByTime(65000);

    // Third request should block and log again
    vi.clearAllMocks();
    await ipWhitelistMiddleware(req, res, next);
    expect(res.status).toHaveBeenCalledWith(200);
    expect(logApp.warn).toHaveBeenCalledTimes(1);
    expect(listener.publishUserAction).toHaveBeenCalledTimes(1);
  });

  it('should allow authenticated user if in exclusion list', async () => {
    vi.mocked(cache.getEntityFromCache as any).mockResolvedValueOnce({
      platform_ip_whitelist_enabled: true,
      platform_ip_whitelist: ['10.0.0.0/8'],
      platform_ip_whitelist_exclusion_ids: ['excluded-group-id'],
    });
    vi.mocked(userDomain.authenticateUserFromRequest as any).mockResolvedValueOnce({ id: 'user1' });

    const mockUsersMap = new Map();
    mockUsersMap.set('user1', { id: 'user1', groups: [{ id: 'excluded-group-id' }] });
    vi.mocked(cache.getEntitiesMapFromCache as any).mockResolvedValueOnce(mockUsersMap);

    await ipWhitelistMiddleware(req, res, next);
    expect(next).toHaveBeenCalled();
  });

  it('should block authenticated user if not in whitelist and not excluded', async () => {
    vi.mocked(cache.getEntityFromCache as any).mockResolvedValueOnce({
      platform_ip_whitelist_enabled: true,
      platform_ip_whitelist: ['10.0.0.0/8'],
      platform_ip_whitelist_exclusion_ids: ['other-group-id'],
    });
    vi.mocked(userDomain.authenticateUserFromRequest as any).mockResolvedValueOnce({ id: 'user1', name: 'User1' });

    const mockUsersMap = new Map();
    mockUsersMap.set('user1', { id: 'user1', groups: [{ id: 'normal-group-id' }] });
    vi.mocked(cache.getEntitiesMapFromCache as any).mockResolvedValueOnce(mockUsersMap);
    req.ip = '203.0.113.2'; // New IP to bypass log throttle
    vi.setSystemTime(new Date('2024-01-01T00:00:00.000Z')); // Ensure log goes through

    await ipWhitelistMiddleware(req, res, next);
    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(200);
    expect(logApp.warn).toHaveBeenCalledTimes(1);
    expect(listener.publishUserAction).toHaveBeenCalledTimes(1);
  });

  it('should handle errors gracefully and call next()', async () => {
    vi.mocked(cache.getEntityFromCache as any).mockRejectedValueOnce(new Error('Cache error'));
    await ipWhitelistMiddleware(req, res, next);
    expect(logApp.error).toHaveBeenCalled();
    expect(next).toHaveBeenCalled(); // Falls open on error
  });
});

// ─── checkIpWhitelistForRequest ─────────────────────────────────────────────

describe('checkIpWhitelistForRequest', () => {
  let req: any;

  beforeEach(() => {
    vi.clearAllMocks();
    req = { ip: '192.168.1.50' };
  });

  it('should return false if IP is whitelisted', async () => {
    vi.mocked(cache.getEntityFromCache as any).mockResolvedValueOnce({
      platform_ip_whitelist_enabled: true,
      platform_ip_whitelist: ['192.168.1.0/24'],
    });
    const result = await checkIpWhitelistForRequest(req, 'user1');
    expect(result).toBe(false);
  });

  it('should return true if IP is not whitelisted and user is not excluded', async () => {
    vi.mocked(cache.getEntityFromCache as any).mockResolvedValueOnce({
      platform_ip_whitelist_enabled: true,
      platform_ip_whitelist: ['10.0.0.0/8'],
    });
    const result = await checkIpWhitelistForRequest(req, 'user1');
    expect(result).toBe(true);
    expect(logApp.warn).toHaveBeenCalledTimes(1);
  });

  it('should return false if user is excluded', async () => {
    vi.mocked(cache.getEntityFromCache as any).mockResolvedValueOnce({
      platform_ip_whitelist_enabled: true,
      platform_ip_whitelist: ['10.0.0.0/8'],
      platform_ip_whitelist_exclusion_ids: ['excluded-user-id'],
    });
    const mockUsersMap = new Map();
    mockUsersMap.set('excluded-user-id', { id: 'excluded-user-id' });
    vi.mocked(cache.getEntitiesMapFromCache as any).mockResolvedValueOnce(mockUsersMap);

    const result = await checkIpWhitelistForRequest(req, 'excluded-user-id');
    expect(result).toBe(false);
  });

  it('should return false on cache error', async () => {
    vi.mocked(cache.getEntityFromCache as any).mockRejectedValueOnce(new Error('Cache fail'));
    const result = await checkIpWhitelistForRequest(req, 'user1');
    expect(result).toBe(false);
    expect(logApp.error).toHaveBeenCalledTimes(1);
  });
});
