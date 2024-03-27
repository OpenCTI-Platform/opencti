import { MeterProvider } from '@opentelemetry/sdk-metrics';
import { type ObservableResult } from '@opentelemetry/api-metrics';

class DynamicTelemetryManager {
  meterProvider: MeterProvider;

  private version = 0;

  constructor(meterProvider: MeterProvider) {
    this.meterProvider = meterProvider;
  }

  setVersion(val: number) {
    this.version = val;
  }

  registerMetrics() {
    const meter = this.meterProvider.getMeter('opencti-api');
    // Register manual metrics
    // - Basic counters
    // TODO
    // - Manual metrics
    const versionGauge = meter.createObservableGauge('opencti-api_version');
    versionGauge.addCallback((observableResult: ObservableResult) => {
      observableResult.observe(this.version);
    });
    // - Library metrics
    // nodeMetrics(this.meterProvider, { prefix: '' }); // TODO: keep or uncomment
  }
}
export const dynamicTelemetryProvider = new MeterProvider({});
export const dynamicTelemetryManager = new DynamicTelemetryManager(dynamicTelemetryProvider);
