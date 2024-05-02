import type { ExportResult } from '@opentelemetry/core/build/src/ExportResult';
import type { ResourceMetrics } from '@opentelemetry/sdk-metrics';
import { InMemoryMetricExporter } from '@opentelemetry/sdk-metrics';
import { logTelemetry } from './conf';

export class MetricFileExporter extends InMemoryMetricExporter {
  // eslint-disable-next-line class-methods-use-this
  export(metrics: ResourceMetrics, resultCallback: (callback: ExportResult) => void) {
    try {
      logTelemetry.info(metrics);
      return resultCallback({ code: 0 });
    } catch (err) {
      return resultCallback({ code: 1, error: err as Error });
    }
  }
}
