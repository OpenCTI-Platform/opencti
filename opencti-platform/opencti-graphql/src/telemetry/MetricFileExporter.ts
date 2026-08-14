import type { ExportResult } from '@opentelemetry/core';
import { InMemoryMetricExporter, type ResourceMetrics } from '@opentelemetry/sdk-metrics';
import { JsonMetricsSerializer } from '@opentelemetry/otlp-transformer';
import { logTelemetry } from '../config/conf';

export class MetricFileExporter extends InMemoryMetricExporter {
  export(metrics: ResourceMetrics, resultCallback: (callback: ExportResult) => void) {
    try {
      const serviceRequest = JsonMetricsSerializer.serializeRequest(metrics);
      if (serviceRequest) {
        const decoder = new TextDecoder();
        logTelemetry.log(decoder.decode(serviceRequest));
      }
      return resultCallback({ code: 0 });
    } catch (err) {
      return resultCallback({ code: 1, error: err as Error });
    }
  }
}
