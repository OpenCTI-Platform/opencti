import { once } from 'node:events';
import https from 'node:https';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { testSync } from '../../../src/domain/connector-utils';
import { buildSelfSignedCertificate } from '../../utils/selfSignedCertificate';
import { testContext, ADMIN_USER } from '../../utils/testQuery';

// Remote OpenCTI stream served over https with a self-signed certificate
let server: https.Server;
let remoteUri: string;

beforeAll(async () => {
  server = https.createServer(buildSelfSignedCertificate(), (_req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/event-stream' });
    res.write(`event: connected\ndata: ${JSON.stringify({ connectionId: 'connection-id' })}\n\n`);
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  remoteUri = `https://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

afterAll(async () => {
  server.closeAllConnections();
  server.close();
});

describe('testSync TLS certificate verification', () => {
  const buildSync = (sslVerify?: boolean | null) => ({ uri: remoteUri, stream_id: 'live', token: '', ssl_verify: sslVerify });

  it.each([undefined, null, true])('should reject an untrusted certificate when ssl_verify is %s', async (sslVerify) => {
    await expect(testSync(testContext, ADMIN_USER, buildSync(sslVerify))).rejects.toThrow('Cant connect to remote opencti');
  });

  it('should accept an untrusted certificate when ssl_verify is disabled', async () => {
    await expect(testSync(testContext, ADMIN_USER, buildSync(false))).resolves.toBe('Connection success');
  });
});
