import * as api from '@opentelemetry/api';
import { internal, ExportResultCode, globalErrorHandler, unrefTimer } from '@opentelemetry/core';
import { diag } from '@opentelemetry/api';
import { type MetricProducer, MetricReader, type PushMetricExporter, TimeoutError } from '@opentelemetry/sdk-metrics';
import { callWithTimeout } from '@opentelemetry/sdk-metrics/build/esnext/utils';
import type { DataPoint, ResourceMetrics } from '@opentelemetry/sdk-metrics/build/src/export/MetricData';
import { Resource } from '@opentelemetry/resources/build/src/Resource';
import { UnknownError } from '../config/errors';
import { logApp } from '../config/conf';

export type BatchExportingMetricReaderOptions = {
  exporter: PushMetricExporter;
  collectIntervalMillis?: number;
  exportIntervalMillis?: number;
  exportTimeoutMillis?: number;
  metricProducers?: MetricProducer[];
  collectCallback?: () => void;
};

export class BatchExportingMetricReader extends MetricReader {
  private _resourceMetrics: ResourceMetrics = { resource: Resource.EMPTY, scopeMetrics: [] };

  private _intervalCollect?: ReturnType<typeof setInterval>;

  private _intervalExport?: ReturnType<typeof setInterval>;

  private readonly _exporter: PushMetricExporter;

  private readonly _collectInterval: number;

  private readonly _exportInterval: number;

  private readonly _exportTimeout: number;

  private _collectCallback:(() => void) | undefined;

  constructor(options: BatchExportingMetricReaderOptions) {
    super({
      aggregationSelector: options.exporter.selectAggregation?.bind(options.exporter),
      aggregationTemporalitySelector: options.exporter.selectAggregationTemporality?.bind(options.exporter),
      metricProducers: options.metricProducers,
    });
    if (options.exportIntervalMillis !== undefined && options.exportIntervalMillis <= 0) {
      throw Error('exportIntervalMillis must be greater than 0');
    }
    if (options.exportTimeoutMillis !== undefined && options.exportTimeoutMillis <= 0) {
      throw Error('exportTimeoutMillis must be greater than 0');
    }
    if (options.exportTimeoutMillis !== undefined && options.exportIntervalMillis !== undefined && options.exportIntervalMillis < options.exportTimeoutMillis) {
      throw Error('exportIntervalMillis must be greater than or equal to exportTimeoutMillis');
    }

    this._collectInterval = options.collectIntervalMillis ?? 60000;
    this._exportInterval = options.exportIntervalMillis ?? 60000;
    this._exportTimeout = options.exportTimeoutMillis ?? 30000;
    this._exporter = options.exporter;
    this._collectCallback = options.collectCallback;
  }

  private async _doRunCollect(): Promise<void> {
    const { resourceMetrics, errors } = await this.collect({ timeoutMillis: this._exportTimeout });
    if (errors.length > 0) {
      api.diag.error(
        'PeriodicExportingMetricReader: metrics collection errors',
        ...errors
      );
    }
    const doCollect = async () => {
      if (this._resourceMetrics.resource !== Resource.EMPTY) {
        // Append result
        const metrics = resourceMetrics.scopeMetrics.map((scopeMetric) => scopeMetric.metrics).flat();
        this._resourceMetrics.scopeMetrics.forEach((value) => {
          value.metrics.forEach((metric) => {
            const findMetric = metrics.filter((newMetric) => newMetric.descriptor.name === metric.descriptor.name);
            const newDataPoints: DataPoint<any>[] = findMetric ? findMetric.map((f) => f.dataPoints).flat() : [];
            metric.dataPoints.push(...newDataPoints);
          });
        });
        logApp.info('[TELEMETRY] metrics collected.', { metrics });
        if (this._collectCallback) {
          this._collectCallback();
        }
      } else {
        logApp.info('[TELEMETRY] resource empty, metrics not collected.');
        this._resourceMetrics = resourceMetrics;
      }
    };

    // Avoid scheduling a promise to make the behavior more predictable and easier to test
    if (resourceMetrics.resource.asyncAttributesPending) {
      resourceMetrics.resource.waitForAsyncAttributes?.()
        .then(doCollect, (err: any) => diag.debug('Error while resolving async portion of resource: ', err));
    } else {
      await doCollect();
    }
  }

  private async _runExportOnce(): Promise<void> {
    try {
      await callWithTimeout(this._doRunExport(), this._exportTimeout);
    } catch (err: any) {
      if (err instanceof TimeoutError) {
        api.diag.error(
          'Export took longer than %s milliseconds and timed out.',
          this._exportTimeout
        );
        return;
      }

      globalErrorHandler(err);
    }
  }

  private async _doRunExport(): Promise<void> {
    const doExport = async () => {
      const result = await internal._export(this._exporter, this._resourceMetrics);
      if (result.code !== ExportResultCode.SUCCESS) {
        throw UnknownError('PeriodicExportingMetricReader: metrics export failed', { cause: result.error });
      }
      this._resourceMetrics.resource = Resource.EMPTY;
    };
    await doExport();
  }

  protected override onInitialized(): void {
    this._intervalCollect = setInterval(() => this._doRunCollect(), this._collectInterval);
    unrefTimer(this._intervalCollect);
    // start running the interval as soon as this reader is initialized and keep handle for shutdown.
    this._intervalExport = setInterval(() => this._runExportOnce(), this._exportInterval);
    unrefTimer(this._intervalExport);
  }

  protected async onForceFlush(): Promise<void> {
    await this._runExportOnce();
    await this._exporter.forceFlush();
  }

  protected async onShutdown(): Promise<void> {
    if (this._intervalExport) {
      clearInterval(this._intervalExport);
    }
    if (this._intervalCollect) {
      clearInterval(this._intervalCollect);
    }
    await this._exporter.shutdown();
  }
}
