import { MeterProvider } from '@opentelemetry/sdk-metrics';
import { LoggerProvider } from '@opentelemetry/sdk-logs';
import type { ObservableResult } from '@opentelemetry/api-metrics';

class FiligranTelemetryManager {
  meterProvider: MeterProvider;

  loggerProvider: LoggerProvider;

  private version = '0';

  private language = 'auto';

  private isEEActivated = false;

  private EEActivationDate = undefined as string | undefined;

  private numberOfInstances = 0;

  constructor(meterProvider: MeterProvider, loggerProvider: LoggerProvider) {
    this.meterProvider = meterProvider;
    this.loggerProvider = loggerProvider;
  }

  setVersion(val: string) {
    this.version = val;
  }

  setLanguage(lang: string) {
    this.language = lang;
  }

  setIsEEActivated(EE: boolean) {
    this.isEEActivated = EE;
  }

  setEEActivationDate(date: string | null | undefined) {
    this.EEActivationDate = date ?? undefined;
  }

  setNumberOfInstances(n: number) {
    this.numberOfInstances = n;
  }

  registerMetrics() {
    const meter = this.meterProvider.getMeter('opencti-api');
    const gauge = meter.createObservableGauge('opencti_api_numberOfInstances');
    gauge.addCallback((observableResult: ObservableResult) => {
      observableResult.observe(this.numberOfInstances);
    });
  }

  registerLogs() {
    const logger = this.loggerProvider.getLogger('opencti-api');
    logger.emit({
      attributes: {
        version: this.version,
        language: this.language,
        isEEActivated: this.isEEActivated,
        EEActivationDate: this.EEActivationDate,
      }
    });
  }

  registerFiligranTelemetry() {
    this.registerMetrics(); // for metrics
    this.registerLogs(); // for string
  }
}
export const filigranTelemetryMeterProvider = new MeterProvider({});
export const filigranTelemetryLoggerProvider = new LoggerProvider();
export const filigranTelemetryManager = new FiligranTelemetryManager(filigranTelemetryMeterProvider, filigranTelemetryLoggerProvider);
