import fs from 'node:fs';
import type { ExportResult } from '@opentelemetry/core/build/src/ExportResult';
import { InMemoryMetricExporter } from '@opentelemetry/sdk-metrics';
import type { ResourceMetrics } from '@opentelemetry/sdk-metrics';
import { AggregationTemporality } from '@opentelemetry/sdk-metrics/build/src/export/AggregationTemporality';

export const FILE_EXPORTER_PATH = '../../../../Documents/fileExporter.txt';

export class MetricFileExporter extends InMemoryMetricExporter {
  constructor(aggregationTemporality: AggregationTemporality, filePath: string) {
    super(aggregationTemporality);
    this.filePath = filePath;
  }

  private filePath;

  export(metrics: ResourceMetrics, resultCallback: (callback: ExportResult) => void) {
    const formattedLogs = metrics;
    fs.appendFile(
      this.filePath,
      `${JSON.stringify(formattedLogs)}\n`,
      (err) => {
        if (err) {
          return resultCallback({ code: 1, error: err });
        }
        return resultCallback({ code: 0 });
      }
    );
  }
}
