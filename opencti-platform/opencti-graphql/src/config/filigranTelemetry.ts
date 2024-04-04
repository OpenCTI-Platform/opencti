import { MeterProvider } from '@opentelemetry/sdk-metrics';
import { LoggerProvider } from '@opentelemetry/sdk-logs';
import type { ObservableResult } from '@opentelemetry/api-metrics';
import { UnknownError } from './errors';

class FiligranTelemetryManager {
  meterProvider: MeterProvider;

  loggerProvider: LoggerProvider;

  private version = '0';

  constructor(meterProvider: MeterProvider, loggerProvider: LoggerProvider) {
    this.meterProvider = meterProvider;
    this.loggerProvider = loggerProvider;
  }

  setVersion(val: string) {
    this.version = val;
  }

  registerMetrics() {
    const meter = this.meterProvider.getMeter('opencti-api');
  }

  registerLogs() {
    const logger = this.loggerProvider.getLogger('opencti-api');
    logger.emit({ body: this.version });
  }

  registerFiligranTelemetry() {
    this.registerMetrics(); // for metrics
    this.registerLogs(); // for string
  }
}
export const filigranTelemetryMeterProvider = new MeterProvider({});
export const filigranTelemetryLoggerProvider = new LoggerProvider();
export const filigranTelemetryManager = new FiligranTelemetryManager(filigranTelemetryMeterProvider, filigranTelemetryLoggerProvider);
