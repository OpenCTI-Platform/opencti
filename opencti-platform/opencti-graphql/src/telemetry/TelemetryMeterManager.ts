import { MeterProvider } from '@opentelemetry/sdk-metrics';
import type { ObservableResult } from '@opentelemetry/api-metrics';
import { ValueType } from '@opentelemetry/api';

export const TELEMETRY_SERVICE_NAME = 'opencti-telemetry';

export class TelemetryMeterManager {
  meterProvider: MeterProvider;

  private isEEActivated = 0;

  private instancesCount = 0;

  private activUsersCount = 0;

  constructor(meterProvider: MeterProvider) {
    this.meterProvider = meterProvider;
  }

  setIsEEActivated(EE: number) {
    this.isEEActivated = EE;
  }

  setInstancesCount(n: number) {
    this.instancesCount = n;
  }

  setActivUsersCount(n: number) {
    this.activUsersCount = n;
  }

  registerFiligranTelemetry() {
    const meter = this.meterProvider.getMeter(TELEMETRY_SERVICE_NAME);
    // - Histogram - //
    // - Gauges - //
    // https://github.com/open-telemetry/opentelemetry-js/issues/3668
    // number of active users
    const activUsersCountGauge = meter.createObservableGauge(
      'opencti_activUsersCount',
      { description: 'number of active users', unit: 'count', valueType: ValueType.INT },
    );
    activUsersCountGauge.addCallback((observableResult: ObservableResult) => {
      observableResult.observe(this.activUsersCount);
    });
    // number of instances
    const instancesCountGauge = meter.createObservableGauge(
      'opencti_instancesCount',
      { description: 'number of instances', unit: 'count', valueType: ValueType.INT },
    );
    instancesCountGauge.addCallback((observableResult: ObservableResult) => {
      observableResult.observe(this.instancesCount);
    });
    // is EE activated
    const isEEActivatedGauge = meter.createObservableGauge(
      'opencti_isEEActivated',
      { description: 'if Enterprise Edition is activated', unit: 'boolean', valueType: ValueType.INT },
    );
    isEEActivatedGauge.addCallback((observableResult: ObservableResult) => {
      observableResult.observe(this.isEEActivated/* , { EEActivationDate: this.EEActivationDate } */);
    });
  }
}
