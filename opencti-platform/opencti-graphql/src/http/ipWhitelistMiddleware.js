import ipaddr from 'ipaddr.js';
import { parse } from 'graphql';
import { getEntityFromCache, getEntitiesMapFromCache } from '../database/cache';
import { ENTITY_TYPE_SETTINGS, ENTITY_TYPE_USER } from '../schema/internalObject';
import { executionContext, SYSTEM_USER } from '../utils/access';
import conf, { logApp } from '../config/conf';
import { isNotEmptyField } from '../database/utils';
import { authenticateUserFromRequest, userWithOrigin } from '../domain/user';
import { publishUserAction } from '../listener/UserActionListener';

// Escape hatch: set app:ip_whitelist_enabled to false in config to bypass
// the whitelist entirely (useful for recovery if admin locks themselves out).
const IP_WHITELIST_CONF_ENABLED = conf.get('app:ip_whitelist_enabled') ?? true;

// Throttle rejection logs: at most one log per IP per window to prevent flooding.
// A browser tab generates many polling requests — without dedup, logs would explode.
const REJECTION_LOG_WINDOW_MS = 60_000; // 1 minute
const REJECTION_LOG_MAX_ENTRIES = 1000;
const rejectionLogCache = new Map(); // ip -> lastLogTimestamp

const shouldLogRejection = (ip) => {
  const now = Date.now();
  const lastLog = rejectionLogCache.get(ip);
  if (lastLog && (now - lastLog) < REJECTION_LOG_WINDOW_MS) {
    return false;
  }
  rejectionLogCache.set(ip, now);
  // Evict stale entries when cache grows too large.
  // First pass: remove entries older than 2× the log window (IPs not seen recently).
  // Fallback: if all entries are recent (e.g. under a brute-force from many IPs),
  // remove the oldest inserted entry — O(1), Map preserves insertion order.
  if (rejectionLogCache.size > REJECTION_LOG_MAX_ENTRIES) {
    for (const [cachedIp, ts] of rejectionLogCache) {
      if ((now - ts) > REJECTION_LOG_WINDOW_MS * 2) {
        rejectionLogCache.delete(cachedIp);
      }
    }
    if (rejectionLogCache.size > REJECTION_LOG_MAX_ENTRIES) {
      rejectionLogCache.delete(rejectionLogCache.keys().next().value);
    }
  }
  return true;
};

/**
 * Checks if a source IP matches at least one entry in the whitelist.
 * Uses ipaddr.js for robust IPv4/IPv6 and CIDR support.
 */
export const ipMatchesWhitelist = (sourceIp, whitelist) => {
  let addr;
  try {
    addr = ipaddr.process(sourceIp);
  } catch {
    return false;
  }

  return whitelist.some((entry) => {
    try {
      if (entry.includes('/')) {
        const [range, prefixLength] = ipaddr.parseCIDR(entry);
        return addr.match(range, prefixLength);
      }
      const target = ipaddr.process(entry);
      return addr.toNormalizedString() === target.toNormalizedString();
    } catch {
      return false;
    }
  });
};

/**
 * Checks if the authenticated user is in the exclusion list (by user ID, group ID, or org ID).
 */
export const isUserExcluded = (user, exclusionIds) => {
  if (!exclusionIds || exclusionIds.length === 0) return false;
  if (!user) return false;

  // Check user ID directly
  if (exclusionIds.includes(user.id) || exclusionIds.includes(user.internal_id)) {
    return true;
  }

  // Check group IDs
  const userGroupIds = (user.groups ?? []).map((g) => g.internal_id ?? g.id);
  if (userGroupIds.some((gid) => exclusionIds.includes(gid))) {
    return true;
  }

  // Check organization IDs
  const userOrgIds = (user.organizations ?? []).map((o) => o.internal_id ?? o.id);
  if (userOrgIds.some((oid) => exclusionIds.includes(oid))) {
    return true;
  }

  return false;
};

// Root fields that must remain accessible to reach the login page, regardless of auth state.
// Validated by parsing the actual query document AST — checks what data is accessed,
// not the arbitrary operation name.
const LOGIN_ALLOWED_FIELDS = new Set([
  'publicSettings',
  'token',
  'otpGeneration',
  'otpValidation',
  'otpLogin',
]);

/**
 * Checks if a GraphQL request only accesses fields from the allowed login set.
 * Parses the actual query document AST to inspect root-level field selections.
 *
 * Returns true only if ALL root selections in ALL operations are in the allowed set.
 */
export const isLoginOnlyRequest = (req) => {
  try {
    if (Array.isArray(req.body)) {
      return req.body.every((item) => item?.query && queryAccessesOnlyLoginFields(item.query));
    }
    return req.body?.query && queryAccessesOnlyLoginFields(req.body.query);
  } catch {
    return false;
  }
};

const queryAccessesOnlyLoginFields = (queryStr) => {
  try {
    const document = parse(queryStr);
    const operations = document.definitions.filter((d) => d.kind === 'OperationDefinition');
    if (operations.length === 0) return false;
    return operations.every((op) => {
      const selections = op.selectionSet?.selections ?? [];
      if (selections.length === 0) return false;
      return selections.every((sel) => sel.kind === 'Field' && LOGIN_ALLOWED_FIELDS.has(sel.name.value));
    });
  } catch {
    return false;
  }
};

/**
 * Express middleware that validates the source IP of each request against a whitelist.
 *
 * Logic:
 * - If platform_ip_whitelist_enabled is false (or not set), allow all.
 * - If IP matches the whitelist, allow.
 * - If request is a login-only operation (verified from query AST), allow (any auth state).
 * - If authenticated and user/group/org is in the exclusion list, allow.
 * - Otherwise, block.
 *
 * Must be mounted AFTER session middleware and BEFORE the GraphQL handler.
 */
const ipWhitelistMiddleware = async (req, res, next) => {
  // Global kill switch via configuration file
  if (!IP_WHITELIST_CONF_ENABLED) return next();

  const sourceIp = req.ip;
  if (!sourceIp) return next();

  try {
    const context = executionContext('ip-whitelist-check');
    const settings = await getEntityFromCache(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);

    // Check if feature is enabled in settings
    if (!settings?.platform_ip_whitelist_enabled) {
      return next();
    }

    const whitelist = settings.platform_ip_whitelist;
    if (!whitelist || whitelist.length === 0) {
      return next();
    }

    // If IP matches the whitelist, always allow (regardless of auth state)
    if (ipMatchesWhitelist(sourceIp, whitelist)) {
      return next();
    }

    // Login-only operations (publicSettings, token, otp*) must always be accessible
    // regardless of authentication state. A blocked user may still have an active session
    // cookie — without this check, the login page itself (publicSettings) would be blocked
    // on refresh, resulting in a blank screen instead of the login form.
    if (isLoginOnlyRequest(req)) {
      return next();
    }

    // IP does NOT match the whitelist — check if request should still be allowed

    // Resolve authenticated user from session or bearer token
    const authenticatedUser = await authenticateUserFromRequest(context, req);

    if (!authenticatedUser) {
      // Block all other unauthenticated requests
      if (shouldLogRejection(sourceIp)) {
        logApp.warn('[IP_WHITELIST] Access denied for unauthenticated IP', { ip: sourceIp });
        await publishUserAction({
          user: SYSTEM_USER,
          event_type: 'authentication',
          event_scope: 'login',
          event_access: 'administration',
          status: 'error',
          context_data: { provider: 'ip_whitelist', username: sourceIp },
        });
      }
      return res.status(200).json({
        data: null,
        errors: [{
          message: 'Your IP address is not allowed to access this platform',
          name: 'IP_FORBIDDEN',
          extensions: { code: 'IP_FORBIDDEN' },
        }],
      });
    }

    // Authenticated (session or token): check exclusion list
    const exclusionIds = settings.platform_ip_whitelist_exclusion_ids;
    if (isNotEmptyField(exclusionIds)) {
      const platformUsers = await getEntitiesMapFromCache(context, SYSTEM_USER, ENTITY_TYPE_USER);
      const fullUser = platformUsers.get(authenticatedUser.id);
      if (fullUser && isUserExcluded(fullUser, exclusionIds)) {
        return next();
      }
    }

    // Authenticated but not excluded and IP not in whitelist → block
    if (shouldLogRejection(sourceIp)) {
      logApp.warn('[IP_WHITELIST] Access denied for IP', { ip: sourceIp, user_id: authenticatedUser.id });
      const auditUser = userWithOrigin(req, authenticatedUser);
      await publishUserAction({
        user: auditUser,
        event_type: 'authentication',
        event_scope: 'login',
        event_access: 'administration',
        status: 'error',
        context_data: { provider: 'ip_whitelist', username: authenticatedUser.user_email ?? authenticatedUser.name },
      });
    }
    return res.status(200).json({
      data: null,
      errors: [{
        message: 'Your IP address is not allowed to access this platform',
        name: 'IP_FORBIDDEN',
        extensions: { code: 'IP_FORBIDDEN' },
      }],
    });
  } catch (error) {
    logApp.error('[IP_WHITELIST] Error checking IP whitelist', { cause: error });
  }

  return next();
};

/**
 * Checks if a request IP is blocked by the whitelist for a given user.
 * Returns true if blocked, false if allowed.
 * Used during SSO callback to reject login for blocked IPs.
 */
export const checkIpWhitelistForRequest = async (req, userId) => {
  if (!IP_WHITELIST_CONF_ENABLED) return false;

  const sourceIp = req.ip;
  if (!sourceIp) return false;

  try {
    const context = executionContext('ip-whitelist-login-check');
    const settings = await getEntityFromCache(context, SYSTEM_USER, ENTITY_TYPE_SETTINGS);

    if (!settings?.platform_ip_whitelist_enabled) return false;
    const whitelist = settings.platform_ip_whitelist;
    if (!whitelist || whitelist.length === 0) return false;

    if (ipMatchesWhitelist(sourceIp, whitelist)) return false;

    // Check exclusion list
    const exclusionIds = settings.platform_ip_whitelist_exclusion_ids;
    if (isNotEmptyField(exclusionIds)) {
      const platformUsers = await getEntitiesMapFromCache(context, SYSTEM_USER, ENTITY_TYPE_USER);
      const fullUser = platformUsers.get(userId);
      if (fullUser && isUserExcluded(fullUser, exclusionIds)) {
        return false;
      }
    }

    logApp.warn('[IP_WHITELIST] Login rejected for IP', { ip: sourceIp, user_id: userId });
    return true;
  } catch (error) {
    logApp.error('[IP_WHITELIST] Error checking IP whitelist during login', { cause: error });
    return false;
  }
};

export default ipWhitelistMiddleware;
