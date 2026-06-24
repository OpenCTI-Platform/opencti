import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import nconf from 'nconf';
import { startLivenessServer, stopLivenessServer } from '../../../../src/http/httpLiveness';
import { basePath } from '../../../../src/config/conf';
import { httpGet, httpPost } from '../../../utils/httpUtils';

const LIVENESS_PORT = nconf.get('app:liveness_port') ?? 4001;
const LIVENESS_URL = `http://localhost:${LIVENESS_PORT}${basePath}/health/liveness`;

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

  it('should return 404 for wrong HTTP POST method', async () => {
    const { statusCode } = await httpPost(LIVENESS_URL, {});
    expect(statusCode).toBe(404);
  });
});
