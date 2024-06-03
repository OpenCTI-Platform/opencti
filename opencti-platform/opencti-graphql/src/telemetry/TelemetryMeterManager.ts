import { MeterProvider } from '@opentelemetry/sdk-metrics';
import type { ObservableResult } from '@opentelemetry/api-metrics';
import { ValueType } from '@opentelemetry/api';

export const TELEMETRY_SERVICE_NAME = 'opencti-telemetry';

export class TelemetryMeterManager {
  meterProvider: MeterProvider;

  // Is enterprise Edition is activated
  isEEActivated = 0;

  // Cluster number of instances
  instancesCount = 0;

  // Number of users in the platform
  usersCount = 0;

  // Number of active users
  activeUsersCount = 0;

  // Number of active connectors
  activeConnectorsCount = 0;

  constructor(meterProvider: MeterProvider) {
    this.meterProvider = meterProvider;
  }

  async shutdown() {
    return this.meterProvider.shutdown();
  }

  setIsEEActivated(EE: number) {
    this.isEEActivated = EE;
  }

  setInstancesCount(n: number) {
    this.instancesCount = n;
  }

  setActiveUsersCount(n: number) {
    this.activeUsersCount = n;
  }

  setUsersCount(n: number) {
    this.usersCount = n;
  }

  setActiveConnectorsCount(n: number) {
    this.activeConnectorsCount = n;
  }

  registerGauge(name: string, description: string, observer: string, opts: { unit?: string, valueType?: ValueType } = {}) {
    const meter = this.meterProvider.getMeter(TELEMETRY_SERVICE_NAME);
    const gaugeOptions = { description, unit: opts.unit ?? 'count', valueType: opts.valueType ?? ValueType.INT };
    const activeUsersCountGauge = meter.createObservableGauge(`opencti_${name}`, gaugeOptions,);
    activeUsersCountGauge.addCallback((observableResult: ObservableResult) => {
      /* eslint-disable @typescript-eslint/ban-ts-comment */
      // @ts-ignore
      observableResult.observe(this[observer]);
    });
  }

  registerFiligranTelemetry() {
    // This kind of gauge count be synchronous, waiting for opentelemetry-js 3668
    // https://github.com/open-telemetry/opentelemetry-js/issues/3668
    this.registerGauge('total_users_count', 'number of users', 'usersCount');
    this.registerGauge('active_users_count', 'number of active users', 'activeUsersCount');
    this.registerGauge('total_instances_count', 'cluster number of instances', 'instancesCount');
    this.registerGauge('active_connectors_count', 'number of active connectors', 'activeConnectorsCount');
    this.registerGauge('is_enterprise_edition', 'enterprise Edition is activated', 'isEEActivated', { unit: 'boolean' });
  }
}
