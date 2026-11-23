import dns, { type LookupAddress, type LookupOptions } from 'node:dns';
import { isIP } from 'node:net';
import ipaddr from 'ipaddr.js';
import { logApp, OUTBOUND_ALLOW_LIST, OUTBOUND_BLOCK_INTERNAL_DESTINATIONS } from '../config/conf';
import { ConfigurationError } from '../config/errors';

/*
 * Outbound requests to internal networks, for the destinations configured by users (ingestion feeds, webhooks, synchronizers).
 * The destination is checked on the resolved IP address, at connection time, so that every redirect hop is covered.
 */

export const INTERNAL_DESTINATION_ERROR_CODE = 'ERR_INTERNAL_DESTINATION_BLOCKED';
const ALLOW_LIST_CONF = 'outbound_requests:allow_list';
const ALLOW_LIST_ENV = 'OUTBOUND_REQUESTS__ALLOW_LIST';
const BLOCK_CONF = 'outbound_requests:block_internal_destinations';

type IPAddress = ipaddr.IPv4 | ipaddr.IPv6;

export type AllowListEntry = { kind: 'range'; range: [IPAddress, number] } | { kind: 'host'; host: string } | { kind: 'domain'; domain: string };

export interface DestinationPolicy {
  blocked: boolean;
  allowList: AllowListEntry[];
}

// A label is 1 to 63 letters, digits, hyphens or underscores (container names), not starting nor ending with a hyphen
const HOST_LABEL = '(?!-)[a-z0-9_-]{1,63}(?<!-)';
const HOST_NAME_PATTERN = new RegExp(`^${HOST_LABEL}(\\.${HOST_LABEL})*$`);
// The URL parser reads a host whose last label is a number as an IPv4 address (10.1 is 10.0.0.1): it is never a host name
const NUMERIC_LABEL_PATTERN = /^(0x[0-9a-f]*|[0-9]+)$/;
const isHostName = (value: string) => HOST_NAME_PATTERN.test(value) && !NUMERIC_LABEL_PATTERN.test(value.slice(value.lastIndexOf('.') + 1));

const normalizeHostName = (hostname: string) => hostname.toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');

// region internal ranges
const embeddedIPv4 = (address: ipaddr.IPv6) => {
  const [high, low] = address.parts.slice(6);
  return new ipaddr.IPv4([high >> 8, high & 0xff, low >> 8, low & 0xff]);
};

const NAT64_WELL_KNOWN_PREFIX = ipaddr.parseCIDR('64:ff9b::/96');

const isInternalIPv4 = (address: ipaddr.IPv4) => address.range() !== 'unicast';

const isInternalIPv6 = (address: ipaddr.IPv6): boolean => {
  // IPv4-mapped (::ffff:a.b.c.d), IPv4-translated (::ffff:0:a.b.c.d) and NAT64 (64:ff9b::a.b.c.d): the IPv4 address is reached
  if (address.isIPv4MappedAddress() || address.range() === 'rfc6145' || address.match(NAT64_WELL_KNOWN_PREFIX)) {
    return isInternalIPv4(embeddedIPv4(address));
  }
  // Deprecated IPv4-compatible addresses (::a.b.c.d), including the unspecified and loopback addresses
  if (address.parts.slice(0, 6).every((part) => part === 0)) {
    return true;
  }
  return address.range() !== 'unicast';
};

/**
 * Every address that is not a global unicast address is internal: loopback, private, link-local, unique local,
 * carrier-grade NAT, multicast, broadcast, unspecified, documentation and other reserved ranges, IPv4 and IPv6.
 */
export const isInternalIPAddress = (address: IPAddress): boolean => {
  return address.kind() === 'ipv6' ? isInternalIPv6(address as ipaddr.IPv6) : isInternalIPv4(address as ipaddr.IPv4);
};

export const isInternalAddress = (address: string): boolean => {
  const normalized = normalizeHostName(address);
  if (!ipaddr.isValid(normalized)) {
    // Not an IP address, nothing can tell where it goes
    return true;
  }
  return isInternalIPAddress(ipaddr.parse(normalized));
};
// endregion

// region allow list
// The resolved IPv4-mapped addresses are matched as IPv4 addresses, so are the IPv4-mapped ranges
const toAllowListRange = (address: IPAddress, prefix: number): AllowListEntry => {
  if (address.kind() === 'ipv6' && (address as ipaddr.IPv6).isIPv4MappedAddress() && prefix >= 96) {
    return { kind: 'range', range: [(address as ipaddr.IPv6).toIPv4Address(), prefix - 96] };
  }
  return { kind: 'range', range: [address, prefix] };
};

const parseAllowListEntry = (entry: string): AllowListEntry => {
  const value = normalizeHostName(entry.trim());
  if (value.includes('/')) {
    // ipaddr.js also accepts the legacy IPv4 forms (10.0.0/8), only the standard ones are allowed
    if (isIP(value.split('/')[0]) === 0 || !ipaddr.isValidCIDR(value)) {
      throw ConfigurationError(`Invalid CIDR range in ${ALLOW_LIST_CONF}`, { entry });
    }
    return toAllowListRange(...ipaddr.parseCIDR(value));
  }
  if (isIP(value) !== 0) {
    const address = ipaddr.parse(value);
    return toAllowListRange(address, address.kind() === 'ipv4' ? 32 : 128);
  }
  if (value.startsWith('*.') && isHostName(value.slice(2))) {
    return { kind: 'domain', domain: value.slice(2) };
  }
  if (isHostName(value)) {
    return { kind: 'host', host: value };
  }
  throw ConfigurationError(`Invalid entry in ${ALLOW_LIST_CONF}, expected a CIDR range, an IP address or a host name`, { entry });
};

export const parseAllowList = (entries: string[]): AllowListEntry[] => entries.map(parseAllowListEntry);

export const isAllowListedHostName = (hostname: string, allowList: AllowListEntry[]) => {
  const host = normalizeHostName(hostname);
  return allowList.some((entry) => (entry.kind === 'host' && entry.host === host)
    || (entry.kind === 'domain' && (host === entry.domain || host.endsWith(`.${entry.domain}`))));
};

const isAllowListedAddress = (address: string, allowList: AllowListEntry[]) => {
  const parsed = ipaddr.process(normalizeHostName(address));
  return allowList.some((entry) => entry.kind === 'range' && entry.range[0].kind() === parsed.kind() && parsed.match(entry.range));
};
// endregion

// region policy
let parsedAllowList: { source: string[]; entries: AllowListEntry[] } | undefined;
export const getDestinationPolicy = (): DestinationPolicy => {
  if (parsedAllowList?.source !== OUTBOUND_ALLOW_LIST) {
    parsedAllowList = { source: OUTBOUND_ALLOW_LIST, entries: parseAllowList(OUTBOUND_ALLOW_LIST) };
  }
  return { blocked: OUTBOUND_BLOCK_INTERNAL_DESTINATIONS, allowList: parsedAllowList.entries };
};

// Log each internal destination once per feature, so that the logs list what to add to the allow list without flooding them
const MAX_LOGGED_DESTINATIONS = 1000;
const loggedDestinations = new Set<string>();
const logOnce = (key: string, log: () => void) => {
  if (loggedDestinations.has(key)) {
    return;
  }
  if (loggedDestinations.size >= MAX_LOGGED_DESTINATIONS) {
    loggedDestinations.clear();
  }
  loggedDestinations.add(key);
  log();
};

// The message reaches the user who configured the destination: it names the host, the resolved address is only logged
export class InternalDestinationError extends Error {
  readonly code = INTERNAL_DESTINATION_ERROR_CODE;

  constructor(feature: string, hostname: string) {
    super(`${feature}: the destination ${hostname} is an internal network address. To allow it, add it to ${ALLOW_LIST_CONF} (${ALLOW_LIST_ENV}).`);
    this.name = 'InternalDestinationError';
  }
}

export interface Destination {
  feature: string;
  hostname: string;
  address: string;
}

/**
 * Tells whether the destination is blocked: its address is internal, not allow-listed, and internal destinations are blocked.
 * An internal destination that is not allow-listed is logged, blocked or not.
 */
export const isBlockedDestination = ({ feature, hostname, address }: Destination, policy = getDestinationPolicy()): boolean => {
  if (!isInternalAddress(address) || isAllowListedHostName(hostname, policy.allowList) || isAllowListedAddress(address, policy.allowList)) {
    return false;
  }
  const meta = { feature, hostname: normalizeHostName(hostname), address: normalizeHostName(address) };
  if (policy.blocked) {
    logOnce(`blocked|${meta.feature}|${meta.hostname}|${meta.address}`, () => {
      logApp.warn(`[OPENCTI] Outbound request to an internal destination blocked, add it to ${ALLOW_LIST_CONF} to allow it`, meta);
    });
    return true;
  }
  logOnce(`allowed|${meta.feature}|${meta.hostname}|${meta.address}`, () => {
    logApp.warn(`[OPENCTI] Outbound request to an internal destination, it will be blocked in an upcoming version unless it is added to ${ALLOW_LIST_CONF}`, meta);
  });
  return false;
};

// Throws an InternalDestinationError when the destination is blocked
export const checkDestination = (destination: Destination, policy = getDestinationPolicy()) => {
  if (isBlockedDestination(destination, policy)) {
    throw new InternalDestinationError(destination.feature, normalizeHostName(destination.hostname));
  }
};

type LookupCallback = (error: NodeJS.ErrnoException | null, address: string | LookupAddress[], family?: number) => void;
type LookupFunction = (hostname: string, options: LookupOptions, callback: LookupCallback) => void;

/**
 * Builds a dns lookup for the connect options of a socket: the host name is resolved, every resolved address is checked,
 * and the socket only connects to the addresses that are not blocked. Node does not call it for a host given as an IP address.
 */
export const buildDestinationLookup = (feature: string, resolve: LookupFunction = dns.lookup as LookupFunction): LookupFunction => {
  return (hostname, options, callback) => {
    resolve(hostname, options, (error, address, family) => {
      if (error) {
        callback(error, address, family);
        return;
      }
      try {
        const policy = getDestinationPolicy();
        if (Array.isArray(address)) {
          // A host with several addresses (IPv4 and IPv6) is reached on its allowed ones only
          const allowed = address.filter((resolved) => !isBlockedDestination({ feature, hostname, address: resolved.address }, policy));
          if (address.length > 0 && allowed.length === 0) {
            callback(new InternalDestinationError(feature, normalizeHostName(hostname)), address, family);
            return;
          }
          callback(null, allowed, family);
          return;
        }
        if (isBlockedDestination({ feature, hostname, address }, policy)) {
          callback(new InternalDestinationError(feature, normalizeHostName(hostname)), address, family);
          return;
        }
      } catch (checkError) {
        callback(checkError as NodeJS.ErrnoException, address, family);
        return;
      }
      callback(null, address, family);
    });
  };
};

type ResolveAll = (hostname: string, options: { all: true }) => Promise<LookupAddress[]>;
const resolveAll: ResolveAll = (hostname, options) => dns.promises.lookup(hostname, options);

/**
 * Checks the destination of a URL before sending the request, when the socket lookup does not run:
 * a host given as an IP address, or a request sent through a proxy, which resolves the host name itself.
 * Behind a proxy, the check is best effort: the proxy resolves the host name again, and a host name that the platform
 * cannot resolve is left to the proxy. Every address must be allowed, as the proxy chooses the one it connects to.
 */
export const checkUrlDestination = async (url: URL, feature: string, viaProxy: boolean, resolve: ResolveAll = resolveAll) => {
  const hostname = normalizeHostName(url.hostname);
  if (isIP(hostname) !== 0) {
    checkDestination({ feature, hostname, address: hostname });
    return;
  }
  if (!viaProxy || isAllowListedHostName(hostname, getDestinationPolicy().allowList)) {
    return;
  }
  let addresses: LookupAddress[];
  try {
    addresses = await resolve(hostname, { all: true });
  } catch (error) {
    logOnce(`unresolved|${feature}|${hostname}`, () => {
      logApp.warn('[OPENCTI] Outbound request destination cannot be resolved by the platform, it is not checked and left to the proxy', { feature, hostname, cause: error });
    });
    return;
  }
  addresses.forEach(({ address }) => checkDestination({ feature, hostname, address }));
};

/**
 * Validates the configuration at startup, and warns while internal destinations are not blocked.
 */
export const checkOutboundRequests = () => {
  const { blocked } = getDestinationPolicy();
  if (!blocked) {
    logApp.warn(`[OPENCTI] Outbound requests to internal networks are allowed for ingestion feeds, webhooks and synchronizers (${BLOCK_CONF}=false). `
      + 'They will be blocked by default in an upcoming version: add the internal destinations you need to '
      + `${ALLOW_LIST_CONF} (${ALLOW_LIST_ENV}), then set OUTBOUND_REQUESTS__BLOCK_INTERNAL_DESTINATIONS=true to opt in now.`);
  }
};
// endregion
