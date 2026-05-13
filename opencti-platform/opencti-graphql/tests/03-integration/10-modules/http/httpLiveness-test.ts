import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import http from 'node:http';
import nconf from 'nconf';
import { startLivenessServer, stopLivenessServer } from '../../../../src/http/httpLiveness';
import { basePath } from '../../../../src/config/conf';

const LIVENESS_PORT = nconf.get('app:liveness_port') ?? 4001;
const LIVENESS_URL = `http://localhost:${LIVENESS_PORT}${basePath}/health/liveness`;

// Helper to make raw HTTP GET requests (no external dependency needed)
const httpGet = (url: string): Promise<{ statusCode: number; body: string }> => {
  return new Promise((resolve, reject) => {
    http.get(url, (res) => {
      let data = '';
      res.on('data', (chunk) => {
        data += chunk;
      });
      res.on('end', () => resolve({ statusCode: res.statusCode ?? 0, body: data }));
    }).on('error', reject);
  });
};

describe('httpLiveness integration tests', () => {
  beforeAll(() => {
    startLivenessServer();
  });

  afterAll(async () => {
    await stopLivenessServer();
  });

  it('should return 200 OK with success status on GET /health/liveness', async () => {
    const { statusCode, body } = await httpGet(LIVENESS_URL);
    expect(statusCode).toBe(200);
    const json = JSON.parse(body);
    expect(json.status).toBe('success');
  });

  it('should return 404 for unknown paths', async () => {
    const { statusCode } = await httpGet(`http://localhost:${LIVENESS_PORT}/unknown`);
    expect(statusCode).toBe(404);
  });

  it('should return 404 for wrong HTTP method (POST simulated as GET to different path)', async () => {
    const { statusCode } = await httpGet(`http://localhost:${LIVENESS_PORT}/`);
    expect(statusCode).toBe(404);
  });
});
