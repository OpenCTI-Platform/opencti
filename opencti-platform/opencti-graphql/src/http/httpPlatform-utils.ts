/**
 * Pure utility functions extracted from httpPlatform for testability.
 */

/**
 * Computes the frame-ancestors CSP directive value from the configured
 * public-dashboard authorized domains string.
 *
 * @param publicDashboardAuthorizedDomains - raw config value
 * @returns A CSP frame-ancestors value ("'none'" when empty)
 */
export const computeFrameAncestors = (publicDashboardAuthorizedDomains: string | undefined | null): string => {
  const ancestorsFromConfig = publicDashboardAuthorizedDomains?.trim() ?? '';
  return ancestorsFromConfig === '' ? "'none'" : ancestorsFromConfig;
};

export interface CspDirectives {
  scriptSrc: string[];
  imgSrc: string[];
  manifestSrc: string[];
  connectSrc: string[];
  objectSrc: string[];
}

/**
 * Builds the Content-Security-Policy directive arrays based on runtime flags.
 *
 * @param devMode - true when running in development mode
 * @param isHttpResourceAllowed - true when HTTP (non-HTTPS) resources are permitted
 */
export const buildCspDirectives = (devMode: boolean, isHttpResourceAllowed: boolean): CspDirectives => {
  const scriptSrc: string[] = ["'self'", "'unsafe-inline'"];
  const imgSrc: string[] = ["'self'", 'data:', 'https://*'];
  const manifestSrc: string[] = ["'self'", 'data:', 'https://*'];
  const connectSrc: string[] = ["'self'", 'wss://*', 'data:', 'https://*'];
  const objectSrc: string[] = ["'self'", 'data:', 'https://*'];

  if (devMode) {
    scriptSrc.push("'unsafe-eval'");
  }

  if (isHttpResourceAllowed) {
    imgSrc.push('http://*');
    manifestSrc.push('http://*');
    connectSrc.push('http://*');
    connectSrc.push('ws://*');
    objectSrc.push('http://*');
  }

  return { scriptSrc, imgSrc, manifestSrc, connectSrc, objectSrc };
};

export type SecurityMiddlewareType = 'public' | 'index' | 'default';

/**
 * Determines which security middleware profile should be applied based on the
 * request URL.
 *
 * @param url - the request URL (req.url)
 * @param appBasePath - the configured base path of the application
 */
export const selectSecurityMiddlewareType = (url: string, appBasePath: string): SecurityMiddlewareType => {
  if (url && url.startsWith(`${appBasePath}/public`)) {
    return 'public';
  }
  if (url && url.includes('/dashboard')) {
    return 'index';
  }
  return 'default';
};

/**
 * Wraps a promise with a timeout – rejects if the promise does not settle
 * within the given duration.
 *
 * @param promise - the promise to race against a timeout
 * @param message - error message used when the timeout fires
 * @param timeoutMs - timeout duration in milliseconds (default 15 000)
 */
export const healthCheckTimeout = async <T>(promise: Promise<T>, message: string, timeoutMs: number = 15000): Promise<T> => {
  const timeoutPromise = new Promise<T>((_, reject) => {
    setTimeout(() => reject(new Error(message)), timeoutMs);
  });
  return Promise.race([promise, timeoutPromise]);
};

