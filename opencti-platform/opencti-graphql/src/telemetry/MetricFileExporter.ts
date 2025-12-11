import type { ExportResult } from '@opentelemetry/core/build/src/ExportResult';
import type { ResourceMetrics } from '@opentelemetry/sdk-metrics';
import { createExportMetricsServiceRequest } from '@opentelemetry/otlp-transformer';
import { InMemoryMetricExporter } from '@opentelemetry/sdk-metrics';
import { logTelemetry } from '../config/conf';

export class MetricFileExporter extends InMemoryMetricExporter {
  // oxlint-disable-next-line class-methods-use-this
  export(metrics: ResourceMetrics, resultCallback: (callback: ExportResult) => void) {
    try {
      const serviceRequest = createExportMetricsServiceRequest([metrics], { useLongBits: false });
      logTelemetry.log(JSON.stringify(serviceRequest));
      return resultCallback({ code: 0 });
    } catch (err) {
      return resultCallback({ code: 1, error: err as Error });
    }
  }
}
