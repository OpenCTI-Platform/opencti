import { MeterProvider } from '@opentelemetry/sdk-metrics';
import { LoggerProvider } from '@opentelemetry/sdk-logs';

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
    // TODO
  }

  registerLogs(timestamp: number) {
    const logger = this.loggerProvider.getLogger('opencti-api');
    const logRecord = {
      body: {
        opencti: {
          settings: {
            language: this.language,
            isEEActivated: this.isEEActivated,
            EEActivationDate: this.EEActivationDate,
            numberOfInstances: this.numberOfInstances,
          },
          version: this.version,
        }
      },
      attributes: {
        timestamp,
      },
    };
    logger.emit(logRecord);
    console.log('logger', logger);
  }

  registerFiligranTelemetry(timestamp: number) {
    this.registerMetrics(); // for metrics
    this.registerLogs(timestamp); // for string
  }
}
export const filigranTelemetryMeterProvider = new MeterProvider({});
export const filigranTelemetryLoggerProvider = new LoggerProvider();
export const filigranTelemetryManager = new FiligranTelemetryManager(filigranTelemetryMeterProvider, filigranTelemetryLoggerProvider);
