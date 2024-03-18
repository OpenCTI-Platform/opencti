import { MeterProvider } from '@opentelemetry/sdk-metrics';
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore
import nodeMetrics from 'opentelemetry-node-metrics';

class DynamicTelemetryManager {
  meterProvider: MeterProvider;

  constructor(meterProvider: MeterProvider) {
    this.meterProvider = meterProvider;
  }

  registerMetrics() {
    const meter = this.meterProvider.getMeter('opencti-api');
    // Register manual metrics
    // - Basic counters
    // TODO
    // - Library metrics
    nodeMetrics(this.meterProvider, { prefix: '' });
  }
}
export const dynamicTelemetryProvider = new MeterProvider({});
export const dynamicTelemetryManager = new DynamicTelemetryManager(dynamicTelemetryProvider);
