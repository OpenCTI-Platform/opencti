import http from 'node:http';
import nconf from 'nconf';
import { basePath, logApp } from '../config/conf';
import { getRateProtectionMaxRequests, getRateProtectionTimeWindowMs } from './httpConfig';

let livenessServer: http.Server | undefined;

// Lightweight in-memory rate limiter for the liveness probe (no Express dependency)
const createRateLimiter = (windowMs: number, maxRequests: number) => {
  const requests = new Map<string, { count: number; resetTime: number }>();
  // Periodically clean up expired entries to avoid memory growth
  const cleanup = setInterval(() => {
    const now = Date.now();
    for (const [ip, entry] of requests) {
      if (now > entry.resetTime) {
        requests.delete(ip);
      }
    }
  }, windowMs);
  cleanup.unref();
  return (ip: string): boolean => {
    const now = Date.now();
    const entry = requests.get(ip);
    if (!entry || now > entry.resetTime) {
      requests.set(ip, { count: 1, resetTime: now + windowMs });
      return true;
    }
    entry.count += 1;
    return entry.count <= maxRequests;
  };
};

/**
 * Start a lightweight HTTP liveness probe server on a dedicated port.
 * This server starts before any platform initialization to allow container
 * orchestrators (e.g. Kubernetes) to detect that the process is alive.
 * It responds HTTP 200 OK to any request on /health/liveness.
 */
export const startLivenessServer = (): void => {
  const livenessPort: number | undefined = nconf.get('app:liveness_port');
  if (!livenessPort) {
    logApp.info('[OPENCTI] Liveness probe disabled (no liveness_port configured)');
    return;
  }
  const isAllowed = createRateLimiter(getRateProtectionTimeWindowMs(), getRateProtectionMaxRequests());

  const livenessPath = `${basePath}/health/liveness`;
  livenessServer = http.createServer((req, res) => {
    const ip = req.socket.remoteAddress ?? 'unknown';
    if (!isAllowed(ip)) {
      res.writeHead(429, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ message: 'Too many requests, please try again later.' }));
      return;
    }
    if (req.url === livenessPath && req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: 'success' }));
    } else {
      res.writeHead(404);
      res.end();
    }
  });
  livenessServer.listen(livenessPort, () => {
    logApp.info(`[OPENCTI] Liveness probe ready on port ${livenessPort} at ${livenessPath}`);
  });
};

export const stopLivenessServer = (): Promise<void> => {
  return new Promise((resolve) => {
    if (livenessServer) {
      livenessServer.close(() => {
        logApp.info('[OPENCTI] Liveness probe stopped');
        resolve();
      });
    } else {
      resolve();
    }
  });
};
