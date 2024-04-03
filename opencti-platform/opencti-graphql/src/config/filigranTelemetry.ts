import { MeterProvider } from '@opentelemetry/sdk-metrics';

class FiligranTelemetryManager {
  meterProvider: MeterProvider;

  private version = '0';

  constructor(meterProvider: MeterProvider) {
    this.meterProvider = meterProvider;
  }

  setVersion(val: string) {
    this.version = val;
  }

  registerMetrics() {
    const meter = this.meterProvider.getMeter('opencti-api');
    // Register manual metrics
  }
}
export const filigranTelemetryProvider = new MeterProvider({});
export const filigranTelemetryManager = new FiligranTelemetryManager(filigranTelemetryProvider);
