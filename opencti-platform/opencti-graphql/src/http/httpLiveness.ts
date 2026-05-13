import http from 'node:http';
import nconf from 'nconf';
import { basePath, logApp } from '../config/conf';

let livenessServer: http.Server | undefined;

/**
 * Start a lightweight HTTP liveness probe server on a dedicated port.
 * This server starts before any platform initialization to allow container
 * orchestrators (e.g. Kubernetes) to detect that the process is alive.
 * It responds HTTP 200 OK to any request on /liveness.
 */
export const startLivenessServer = (): void => {
  const livenessPort: number | undefined = nconf.get('app:liveness_port');
  if (!livenessPort) {
    logApp.info('[OPENCTI] Liveness probe disabled (no liveness_port configured)');
    return;
  }
  const livenessPath = `${basePath}/health/liveness`;
  livenessServer = http.createServer((req, res) => {
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
