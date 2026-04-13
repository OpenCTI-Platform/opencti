import { OTLPMetricExporter, type OTLPMetricExporterOptions } from '@opentelemetry/exporter-metrics-otlp-http';
import { logTelemetry } from '../config/conf';
import type { ExportResult } from '@opentelemetry/core';
import type { ResourceMetrics } from '@opentelemetry/sdk-metrics';

export class MetricFileExporter extends OTLPMetricExporter {
  constructor(config?: OTLPMetricExporterOptions) {
    super({
      ...config,
      headers: {
        'Content-Type': 'application/json',
      },
    });
  }

  override export(items: ResourceMetrics, resultCallback: (result: ExportResult) => void): void {
    logTelemetry.log(items);
    return OTLPMetricExporter.prototype.export(items, resultCallback);
  }
}
