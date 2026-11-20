import type { LookupAddress, LookupOptions } from 'node:dns';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { logApp } from '../../../src/config/conf';
import {
  buildDestinationLookup,
  checkDestination,
  checkOutboundRequests,
  checkUrlDestination,
  INTERNAL_DESTINATION_ERROR_CODE,
  InternalDestinationError,
  isInternalAddress,
  parseAllowList,
} from '../../../src/utils/internal-destination';

// outbound_requests configuration, the real configuration values are used when not overridden
const outboundConfig = vi.hoisted(() => ({ blocked: undefined as boolean | undefined, allowList: undefined as string[] | undefined }));
vi.mock('../../../src/config/conf', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../src/config/conf')>();
  return {
    ...actual,
    get OUTBOUND_BLOCK_INTERNAL_DESTINATIONS() {
      return outboundConfig.blocked ?? actual.OUTBOUND_BLOCK_INTERNAL_DESTINATIONS;
    },
    get OUTBOUND_ALLOW_LIST() {
      return outboundConfig.allowList ?? actual.OUTBOUND_ALLOW_LIST;
    },
  };
});

type Resolved = string | LookupAddress[];
const fakeResolver = (resolved: Resolved | Error) => {
  return (_hostname: string, _options: LookupOptions, callback: (error: NodeJS.ErrnoException | null, address: Resolved, family?: number) => void) => {
    if (resolved instanceof Error) {
      callback(resolved, '');
    } else {
      callback(null, resolved, typeof resolved === 'string' ? 4 : undefined);
    }
  };
};
const runLookup = (feature: string, hostname: string, resolved: Resolved | Error, options: LookupOptions = {}) => new Promise<Resolved>((resolve, reject) => {
  buildDestinationLookup(feature, fakeResolver(resolved))(hostname, options, (error, address) => (error ? reject(error) : resolve(address)));
});

afterEach(() => {
  outboundConfig.blocked = undefined;
  outboundConfig.allowList = undefined;
  vi.restoreAllMocks();
});

describe('isInternalAddress', () => {
  it.each([
    ['127.0.0.1', 'IPv4 loopback'],
    ['127.255.255.254', 'IPv4 loopback range'],
    ['10.1.2.3', 'IPv4 private 10/8'],
    ['172.16.0.1', 'IPv4 private 172.16/12'],
    ['172.31.255.255', 'IPv4 private 172.16/12 upper bound'],
    ['192.168.1.1', 'IPv4 private 192.168/16'],
    ['169.254.169.254', 'IPv4 link-local, cloud metadata'],
    ['100.64.0.1', 'IPv4 carrier-grade NAT'],
    ['0.0.0.0', 'IPv4 unspecified'],
    ['255.255.255.255', 'IPv4 broadcast'],
    ['224.0.0.1', 'IPv4 multicast'],
    ['192.0.2.10', 'IPv4 documentation'],
    ['198.18.0.1', 'IPv4 benchmarking'],
    ['240.0.0.1', 'IPv4 reserved'],
    ['::1', 'IPv6 loopback'],
    ['[::1]', 'IPv6 loopback between brackets'],
    ['::', 'IPv6 unspecified'],
    ['fe80::1', 'IPv6 link-local'],
    ['fc00::1', 'IPv6 unique local'],
    ['fd12:3456:789a::1', 'IPv6 unique local fd00::/8'],
    ['fec0::1', 'IPv6 deprecated site-local'],
    ['ff02::1', 'IPv6 multicast'],
    ['2001:db8::1', 'IPv6 documentation'],
    ['::ffff:127.0.0.1', 'IPv4-mapped loopback'],
    ['::ffff:7f00:1', 'IPv4-mapped loopback, hexadecimal form'],
    ['::ffff:10.0.0.1', 'IPv4-mapped private'],
    ['::ffff:a9fe:a9fe', 'IPv4-mapped link-local'],
    ['::ffff:0:a00:1', 'IPv4-translated private'],
    ['::127.0.0.1', 'IPv4-compatible loopback'],
    ['64:ff9b::7f00:1', 'NAT64 loopback'],
    ['64:ff9b::a00:1', 'NAT64 private'],
    ['64:ff9b:1::1', 'NAT64 local-use prefix'],
  ])('should treat %s as internal (%s)', (address) => {
    expect(isInternalAddress(address)).toBe(true);
  });

  it.each([
    ['8.8.8.8', 'IPv4 public'],
    ['1.1.1.1', 'IPv4 public'],
    ['172.32.0.1', 'IPv4 public just above 172.16/12'],
    ['100.128.0.1', 'IPv4 public just above carrier-grade NAT'],
    ['2606:4700:4700::1111', 'IPv6 public'],
    ['2a00:1450:4007:80c::200e', 'IPv6 public'],
    ['::ffff:8.8.8.8', 'IPv4-mapped public'],
    ['64:ff9b::808:808', 'NAT64 public'],
  ])('should treat %s as public (%s)', (address) => {
    expect(isInternalAddress(address)).toBe(false);
  });
});

describe('parseAllowList', () => {
  it('should accept CIDR ranges, IP addresses, host names and wildcard domains', () => {
    const entries = parseAllowList(['10.0.0.0/8', 'fd00::/8', '192.168.1.10', '::1', 'misp.internal', 'MISP-2.Corp.Local.', '*.corp.local', 'opencti_misp_1']);
    expect(entries.map((entry) => entry.kind)).toEqual(['range', 'range', 'range', 'range', 'host', 'host', 'domain', 'host']);
    expect(entries[5]).toEqual({ kind: 'host', host: 'misp-2.corp.local' });
    expect(entries[6]).toEqual({ kind: 'domain', domain: 'corp.local' });
    expect(entries[7]).toEqual({ kind: 'host', host: 'opencti_misp_1' });
  });

  it('should read IPv4-mapped ranges as IPv4 ranges', () => {
    const [range, address] = parseAllowList(['::ffff:10.0.0.0/104', '::ffff:192.168.1.10']);
    expect(range.kind === 'range' && range.range[0].toString()).toBe('10.0.0.0');
    expect(range.kind === 'range' && range.range[1]).toBe(8);
    expect(address.kind === 'range' && address.range[0].toString()).toBe('192.168.1.10');
    expect(address.kind === 'range' && address.range[1]).toBe(32);
  });

  it.each(['10.0.0.0/33', '10.0.0/8', 'http://misp.internal', 'misp.internal:8080', '-misp.internal', 'misp internal', '*.', '*', '10.1', '0x7f.1', 'misp.0x10', '*.10.1'])(
    'should reject the invalid entry %s',
    (entry) => {
      expect(() => parseAllowList([entry])).toThrow('outbound_requests:allow_list');
    },
  );
});

describe('checkDestination', () => {
  const blockedPolicy = (allowList: string[] = []) => ({ blocked: true, allowList: parseAllowList(allowList) });

  it('should allow a public destination', () => {
    expect(() => checkDestination({ feature: 'CSV feed', hostname: 'feed.example.com', address: '93.184.216.34' }, blockedPolicy())).not.toThrow();
  });

  it('should reject an internal destination with an error that names the allow list', () => {
    let error: unknown;
    try {
      checkDestination({ feature: 'CSV feed', hostname: 'misp.internal', address: '10.0.0.5' }, blockedPolicy());
    } catch (e) {
      error = e;
    }
    expect(error).toBeInstanceOf(InternalDestinationError);
    expect((error as InternalDestinationError).code).toBe(INTERNAL_DESTINATION_ERROR_CODE);
    expect((error as Error).message).toBe('CSV feed: the destination misp.internal is an internal network address. '
      + 'To allow it, add it to outbound_requests:allow_list (OUTBOUND_REQUESTS__ALLOW_LIST).');
  });

  it.each([
    ['a CIDR range', ['10.0.0.0/8'], 'misp.internal', '10.0.0.5'],
    ['an IP address', ['10.0.0.5'], 'misp.internal', '10.0.0.5'],
    ['an IPv4 range for an IPv4-mapped address', ['10.0.0.0/8'], 'misp.internal', '::ffff:10.0.0.5'],
    ['an IPv4-mapped range for an IPv4 address', ['::ffff:10.0.0.0/104'], 'misp.internal', '10.0.0.5'],
    ['a host name with an underscore', ['opencti_misp_1'], 'opencti_misp_1', '172.18.0.5'],
    ['an IPv6 range', ['fd00::/8'], 'misp.internal', 'fd00::5'],
    ['a host name', ['misp.internal'], 'MISP.internal', '10.0.0.5'],
    ['a wildcard domain', ['*.internal'], 'misp.internal', '10.0.0.5'],
  ])('should allow an internal destination allow-listed by %s', (_, allowList, hostname, address) => {
    expect(() => checkDestination({ feature: 'CSV feed', hostname, address }, blockedPolicy(allowList))).not.toThrow();
  });

  it('should not allow an internal destination outside the allow list', () => {
    expect(() => checkDestination({ feature: 'CSV feed', hostname: 'other.local', address: '10.0.0.5' }, blockedPolicy(['192.168.0.0/16', 'misp.internal'])))
      .toThrow(InternalDestinationError);
  });

  it('should log a blocked internal destination with its address once per feature', () => {
    const warn = vi.spyOn(logApp, 'warn');
    const policy = blockedPolicy();
    expect(() => checkDestination({ feature: 'Blocked log feed', hostname: 'misp.internal', address: '10.0.0.7' }, policy)).toThrow(InternalDestinationError);
    expect(() => checkDestination({ feature: 'Blocked log feed', hostname: 'misp.internal', address: '10.0.0.7' }, policy)).toThrow(InternalDestinationError);
    expect(warn).toHaveBeenCalledTimes(1);
    expect(warn).toHaveBeenCalledWith(expect.stringContaining('blocked'), { feature: 'Blocked log feed', hostname: 'misp.internal', address: '10.0.0.7' });
  });

  it('should allow and log an internal destination once per feature when internal destinations are not blocked', () => {
    const warn = vi.spyOn(logApp, 'warn');
    const policy = { blocked: false, allowList: [] };
    checkDestination({ feature: 'Log once feed', hostname: 'misp.internal', address: '10.0.0.6' }, policy);
    checkDestination({ feature: 'Log once feed', hostname: 'misp.internal', address: '10.0.0.6' }, policy);
    checkDestination({ feature: 'Log once webhook', hostname: 'misp.internal', address: '10.0.0.6' }, policy);
    expect(warn).toHaveBeenCalledTimes(2);
    expect(warn).toHaveBeenCalledWith(expect.stringContaining('outbound_requests:allow_list'), { feature: 'Log once feed', hostname: 'misp.internal', address: '10.0.0.6' });
    expect(warn).toHaveBeenCalledWith(expect.stringContaining('outbound_requests:allow_list'), { feature: 'Log once webhook', hostname: 'misp.internal', address: '10.0.0.6' });
  });

  it('should read the policy from the configuration', () => {
    outboundConfig.blocked = true;
    outboundConfig.allowList = ['10.0.0.0/24'];
    expect(() => checkDestination({ feature: 'CSV feed', hostname: 'a.internal', address: '10.0.0.5' })).not.toThrow();
    expect(() => checkDestination({ feature: 'CSV feed', hostname: 'b.internal', address: '10.0.1.5' })).toThrow(InternalDestinationError);
  });
});

describe('buildDestinationLookup', () => {
  it('should resolve a public host name', async () => {
    outboundConfig.blocked = true;
    await expect(runLookup('CSV feed', 'feed.example.com', '93.184.216.34')).resolves.toBe('93.184.216.34');
  });

  it('should reject a host name resolving to an internal address', async () => {
    outboundConfig.blocked = true;
    await expect(runLookup('CSV feed', 'rebind.example.com', '127.0.0.1')).rejects.toThrow('CSV feed: the destination rebind.example.com is an internal');
  });

  it('should reject a host name when all its addresses are internal', async () => {
    outboundConfig.blocked = true;
    const addresses = [{ address: '127.0.0.1', family: 4 }, { address: '::1', family: 6 }];
    await expect(runLookup('CSV feed', 'localhost', addresses, { all: true })).rejects.toThrow(InternalDestinationError);
  });

  it('should only keep the public addresses of a host name with internal ones', async () => {
    outboundConfig.blocked = true;
    const addresses = [{ address: '93.184.216.34', family: 4 }, { address: 'fd00::1', family: 6 }];
    await expect(runLookup('CSV feed', 'mixed.example.com', addresses, { all: true })).resolves.toEqual([{ address: '93.184.216.34', family: 4 }]);
  });

  it('should only keep the allow-listed addresses of a dual-stack internal host', async () => {
    outboundConfig.blocked = true;
    outboundConfig.allowList = ['10.0.0.0/8'];
    const addresses = [{ address: '10.0.0.5', family: 4 }, { address: 'fd00::5', family: 6 }];
    await expect(runLookup('CSV feed', 'misp.internal', addresses, { all: true })).resolves.toEqual([{ address: '10.0.0.5', family: 4 }]);
  });

  it('should keep every address of an internal host when internal destinations are not blocked', async () => {
    outboundConfig.blocked = false;
    const addresses = [{ address: '10.0.0.5', family: 4 }, { address: 'fd00::5', family: 6 }];
    await expect(runLookup('CSV feed', 'misp.internal', addresses, { all: true })).resolves.toEqual(addresses);
  });

  it('should resolve every address of a public host name', async () => {
    outboundConfig.blocked = true;
    const addresses = [{ address: '93.184.216.34', family: 4 }, { address: '2606:2800:220:1::248', family: 6 }];
    await expect(runLookup('CSV feed', 'feed.example.com', addresses, { all: true })).resolves.toEqual(addresses);
  });

  it('should resolve an allow-listed internal host name', async () => {
    outboundConfig.blocked = true;
    outboundConfig.allowList = ['misp.internal'];
    await expect(runLookup('CSV feed', 'misp.internal', '10.0.0.5')).resolves.toBe('10.0.0.5');
  });

  it('should resolve an internal host name when internal destinations are not blocked', async () => {
    outboundConfig.blocked = false;
    await expect(runLookup('CSV feed', 'misp.internal', '10.0.0.5')).resolves.toBe('10.0.0.5');
  });

  it('should forward a resolution error', async () => {
    const notFound = Object.assign(new Error('getaddrinfo ENOTFOUND unknown.example.com'), { code: 'ENOTFOUND' });
    await expect(runLookup('CSV feed', 'unknown.example.com', notFound)).rejects.toBe(notFound);
  });
});

describe('checkUrlDestination', () => {
  const resolveTo = (address: string) => vi.fn(async () => [{ address, family: address.includes(':') ? 6 : 4 }]);

  it('should check an IP address without resolving it', async () => {
    outboundConfig.blocked = true;
    const resolver = resolveTo('93.184.216.34');
    await expect(checkUrlDestination(new URL('http://169.254.169.254/latest/meta-data'), 'Webhook', false, resolver)).rejects.toThrow(InternalDestinationError);
    await expect(checkUrlDestination(new URL('http://[::ffff:127.0.0.1]:8080/'), 'Webhook', false, resolver)).rejects.toThrow(InternalDestinationError);
    await expect(checkUrlDestination(new URL('http://2130706433/'), 'Webhook', false, resolver)).rejects.toThrow('127.0.0.1');
    await expect(checkUrlDestination(new URL('http://93.184.216.34/'), 'Webhook', false, resolver)).resolves.toBeUndefined();
    expect(resolver).not.toHaveBeenCalled();
  });

  it('should leave a host name to the socket lookup without a proxy', async () => {
    outboundConfig.blocked = true;
    const resolver = resolveTo('127.0.0.1');
    await expect(checkUrlDestination(new URL('http://localhost/'), 'Webhook', false, resolver)).resolves.toBeUndefined();
    expect(resolver).not.toHaveBeenCalled();
  });

  it('should resolve and check a host name behind a proxy', async () => {
    outboundConfig.blocked = true;
    await expect(checkUrlDestination(new URL('https://misp.internal/'), 'CSV feed', true, resolveTo('10.0.0.5'))).rejects.toThrow('the destination misp.internal is an internal');
    await expect(checkUrlDestination(new URL('https://feed.example.com/'), 'CSV feed', true, resolveTo('93.184.216.34'))).resolves.toBeUndefined();
  });

  it('should not resolve an allow-listed host name behind a proxy', async () => {
    outboundConfig.blocked = true;
    outboundConfig.allowList = ['misp.internal'];
    const resolver = resolveTo('10.0.0.5');
    await expect(checkUrlDestination(new URL('https://misp.internal/'), 'CSV feed', true, resolver)).resolves.toBeUndefined();
    expect(resolver).not.toHaveBeenCalled();
  });

  it('should leave a host name that the platform cannot resolve to the proxy, with a warning', async () => {
    outboundConfig.blocked = true;
    const warn = vi.spyOn(logApp, 'warn');
    const resolver = vi.fn(async () => {
      throw Object.assign(new Error('getaddrinfo ENOTFOUND feed.example.com'), { code: 'ENOTFOUND' });
    });
    await expect(checkUrlDestination(new URL('https://feed.example.com/'), 'CSV feed', true, resolver)).resolves.toBeUndefined();
    expect(warn).toHaveBeenCalledWith(expect.stringContaining('cannot be resolved'), expect.objectContaining({ feature: 'CSV feed', hostname: 'feed.example.com' }));
  });

  it('should reject a host name behind a proxy when one of its addresses is internal', async () => {
    outboundConfig.blocked = true;
    const resolver = vi.fn(async () => [{ address: '93.184.216.34', family: 4 }, { address: '10.0.0.5', family: 4 }]);
    await expect(checkUrlDestination(new URL('https://mixed.example.com/'), 'CSV feed', true, resolver)).rejects.toThrow(InternalDestinationError);
  });
});

describe('checkOutboundRequests', () => {
  it('should warn at startup while internal destinations are not blocked', () => {
    const warn = vi.spyOn(logApp, 'warn');
    outboundConfig.blocked = false;
    checkOutboundRequests();
    expect(warn).toHaveBeenCalledWith(expect.stringContaining('OUTBOUND_REQUESTS__BLOCK_INTERNAL_DESTINATIONS=true'));
  });

  it('should not warn when internal destinations are blocked', () => {
    const warn = vi.spyOn(logApp, 'warn');
    outboundConfig.blocked = true;
    checkOutboundRequests();
    expect(warn).not.toHaveBeenCalled();
  });

  it('should fail on an invalid allow list', () => {
    outboundConfig.allowList = ['not a host'];
    expect(() => checkOutboundRequests()).toThrow('outbound_requests:allow_list');
  });
});
