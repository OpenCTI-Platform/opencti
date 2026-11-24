import { PrometheusExporter } from '@opentelemetry/exporter-prometheus';
import { logApp } from '../config/conf';

/**
 * Builds the Prometheus exporter that exposes the Filigran telemetry metrics for scraping.
 *
 * Returns undefined when no port is configured: the endpoint is off by default.
 * A server that cannot start (port already taken, for example) is reported through
 * logApp, since the exporter itself only sends that error to OpenTelemetry's diag,
 * which has no logger in this platform.
 *
 * @param port Port the endpoint listens on; unset keeps the endpoint off.
 * @param host IPv4 address the endpoint listens on. Always passed: since
 * @opentelemetry/exporter-prometheus 0.300.0, an unset host listens on localhost only.
 * @returns The exporter to register as a metric reader, or undefined when disabled.
 */
export const buildFiligranPrometheusExporter = (
  port: number | undefined,
  host: string,
): PrometheusExporter | undefined => {
  if (!port) {
    return undefined;
  }
  return new PrometheusExporter(
    {
      host,
      port,
    },
    (err) => {
      if (err) {
        logApp.warn('[TELEMETRY] Prometheus exporter could not start', {
          cause: err,
          host,
          port,
        });
      } else {
        logApp.info('[TELEMETRY] Prometheus exporter activated', {
          host,
          port,
        });
      }
    },
  );
};
