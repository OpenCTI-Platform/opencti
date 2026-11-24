import { createServer, type Server } from 'node:net';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { PrometheusExporter } from '@opentelemetry/exporter-prometheus';
import { buildFiligranPrometheusExporter } from '../../../src/telemetry/filigranPrometheusExporter';
import { logApp } from '../../../src/config/conf';

const HOST = '127.0.0.1';

/**
 * Opens a TCP server on a free port, so the test owns that port.
 *
 * @returns The listening server and the port it holds.
 */
const listenOnFreePort = async (): Promise<{
  server: Server;
  port: number;
}> => {
  const server = createServer();
  await new Promise<void>((resolve) => {
    server.listen(0, HOST, resolve);
  });
  const address = server.address();
  if (!address || typeof address === 'string') {
    throw new Error('Expected a TCP address');
  }
  return {
    server,
    port: address.port,
  };
};

/**
 * Closes a TCP server.
 *
 * @param server The server to close.
 */
const closeServer = (server: Server) => new Promise<void>((resolve) => {
  server.close(() => resolve());
});

/**
 * Waits until the exporter has reported whether its server started.
 */
const waitForStartReport = () => vi.waitFor(() => {
  const reported = vi.mocked(logApp.info).mock.calls.length + vi.mocked(logApp.warn).mock.calls.length;
  expect(reported).toBeGreaterThan(0);
});

describe('buildFiligranPrometheusExporter', () => {
  let exporter: PrometheusExporter | undefined;

  beforeEach(() => {
    vi.spyOn(logApp, 'info').mockImplementation(() => {});
    vi.spyOn(logApp, 'warn').mockImplementation(() => {});
  });

  afterEach(async () => {
    await exporter?.shutdown();
    exporter = undefined;
    vi.restoreAllMocks();
  });

  it('should not build an exporter when no port is configured', () => {
    exporter = buildFiligranPrometheusExporter(undefined, HOST);
    expect(exporter).toBeUndefined();
  });

  it('should serve the metrics endpoint and log the activation', async () => {
    const { server, port } = await listenOnFreePort();
    await closeServer(server);

    exporter = buildFiligranPrometheusExporter(port, HOST);
    await waitForStartReport();

    expect(logApp.info).toHaveBeenCalledWith('[TELEMETRY] Prometheus exporter activated', {
      host: HOST,
      port,
    });
    expect(logApp.warn).not.toHaveBeenCalled();
    const response = await fetch(`http://${HOST}:${port}/metrics`);
    expect(response.status).toBe(200);
  });

  it('should log a warning instead of the activation when the port is already taken', async () => {
    const { server, port } = await listenOnFreePort();
    try {
      exporter = buildFiligranPrometheusExporter(port, HOST);
      await waitForStartReport();

      expect(logApp.warn).toHaveBeenCalledWith('[TELEMETRY] Prometheus exporter could not start', {
        cause: expect.objectContaining({ code: 'EADDRINUSE' }),
        host: HOST,
        port,
      });
      expect(logApp.info).not.toHaveBeenCalled();
    } finally {
      await closeServer(server);
    }
  });
});
