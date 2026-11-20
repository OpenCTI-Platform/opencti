import bytes from 'bytes';
import nconf from 'nconf';
import { booleanConf, DEV_MODE } from '../config/conf';
import { stringArrayConf } from '../config/conf-utils';

const PUBLIC_AUTH_DOMAINS: string = nconf.get('app:public_dashboard_authorized_domains') ?? '';
export const getPublicAuthorizedDomainsFromConfiguration = () => {
  return PUBLIC_AUTH_DOMAINS.trim();
};

// Global HTTP hardening, fallback for the HTTP protections that do not define their own option.
// Disabled by default for now, it will be enabled by default in an upcoming version.
const HTTP_SECURE_BY_DEFAULT: boolean = booleanConf('app:http:secure_by_default', false);
export const isHttpSecureByDefault = () => {
  return HTTP_SECURE_BY_DEFAULT;
};

const IS_HTTP_ALLOWED: boolean = booleanConf('app:allow_unsecure_http_resources', !HTTP_SECURE_BY_DEFAULT);
export const isUnsecureHttpResourceAllowed = () => {
  return IS_HTTP_ALLOWED;
};

// upgrade-insecure-requests also makes the browser load the platform's own resources over HTTPS,
// which breaks a platform served over plain HTTP: only an explicit app:allow_unsecure_http_resources=false sends it, not the switch.
const UPGRADE_INSECURE_REQUESTS: boolean = !booleanConf('app:allow_unsecure_http_resources', true);
export const isUpgradeInsecureRequestsEnabled = () => {
  return UPGRADE_INSECURE_REQUESTS;
};

export const isDevMode = () => {
  return DEV_MODE;
};

const RATE_PROTECTION_IP_SKIP_LIST: string[] = stringArrayConf('app:rate_protection:ip_skip_list');
export const getRateProtectionIpSkipList = () => {
  return RATE_PROTECTION_IP_SKIP_LIST;
};

const RATE_PROTECTION_IP_SKIP_RANGES: string[] = stringArrayConf('app:rate_protection:ip_skip_ranges');
export const getRateProtectionIpSkipRanges = () => {
  return RATE_PROTECTION_IP_SKIP_RANGES;
};

const RATE_PROTECTION_USER_AGENT_SKIP_PREFIXES: string[] = stringArrayConf('app:rate_protection:user_agent_skip_prefixes');
export const getRateProtectionUserAgentSkipPrefixes = () => {
  return RATE_PROTECTION_USER_AGENT_SKIP_PREFIXES;
};

const RATE_PROTECTION_TIME_WINDOW: number = nconf.get('app:rate_protection:time_window') ?? (HTTP_SECURE_BY_DEFAULT ? 60 : 1);
export const getRateProtectionTimeWindowMs = () => {
  return RATE_PROTECTION_TIME_WINDOW < 1 ? 1000 : RATE_PROTECTION_TIME_WINDOW * 1000;
};

const RATE_PROTECTION_MAX_REQUESTS: number = nconf.get('app:rate_protection:max_requests') ?? (HTTP_SECURE_BY_DEFAULT ? 30000 : 10000);
export const getRateProtectionMaxRequests = () => {
  return RATE_PROTECTION_MAX_REQUESTS;
};

// Limit of the JSON bodies (GraphQL, TAXII, REST), also applied to the GraphQL multipart 'operations' field.
const MAX_PAYLOAD_BODY_SIZE: string | number = nconf.get('app:max_payload_body_size') || (HTTP_SECURE_BY_DEFAULT ? '10mb' : '50mb');
export const getMaxPayloadBodySize = () => {
  return MAX_PAYLOAD_BODY_SIZE;
};
// Same limit in bytes, as parsed by express.json, for the TAXII API root to advertise what it accepts.
export const getMaxPayloadBodySizeInBytes = () => {
  return bytes.parse(MAX_PAYLOAD_BODY_SIZE);
};

// Number of redirects followed by the outgoing requests of the platform HTTP client (feeds, synchronizers, notifiers...).
// A value from a JSON file stays a string. Anything but a non-negative safe integer falls back to the default.
const HTTP_MAX_REDIRECTS_RAW: unknown = nconf.get('app:http:max_redirects');
const HTTP_MAX_REDIRECTS_CONF: string = String(HTTP_MAX_REDIRECTS_RAW).trim();
const HTTP_MAX_REDIRECTS_PARSED: number = /^\d+$/.test(HTTP_MAX_REDIRECTS_CONF) ? Number(HTTP_MAX_REDIRECTS_CONF) : NaN;
const IS_HTTP_MAX_REDIRECTS_VALID: boolean = Number.isSafeInteger(HTTP_MAX_REDIRECTS_PARSED);
const HTTP_MAX_REDIRECTS: number = IS_HTTP_MAX_REDIRECTS_VALID ? HTTP_MAX_REDIRECTS_PARSED : (HTTP_SECURE_BY_DEFAULT ? 5 : 21);
export const getHttpMaxRedirects = () => {
  return HTTP_MAX_REDIRECTS;
};
// Configured value replaced by the default, reported at startup so the admin knows it is not applied.
export const getInvalidHttpMaxRedirects = (): string | undefined => {
  const isConfigured = HTTP_MAX_REDIRECTS_RAW !== undefined && HTTP_MAX_REDIRECTS_CONF !== '';
  return isConfigured && !IS_HTTP_MAX_REDIRECTS_VALID ? HTTP_MAX_REDIRECTS_CONF : undefined;
};

// Node.js defaults keepAliveTimeout to 5s, which is lower than the idle timeout of most load
// balancers and reverse proxies (AWS ALB defaults to 60s). The platform then closes sockets the
// load balancer still considers usable, producing intermittent 502 for the clients. Defaulting
// above the usual 60s idle timeout removes the race for standard deployments.
const KEEP_ALIVE_TIMEOUT: number = nconf.get('app:keep_alive_timeout') ?? 65000;
export const getKeepAliveTimeout = () => {
  return KEEP_ALIVE_TIMEOUT;
};
