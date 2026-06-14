import { describe, expect, it } from 'vitest';
import { ipMatchesWhitelist, isUserExcluded } from '../../../src/http/ipWhitelistMiddleware';

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
