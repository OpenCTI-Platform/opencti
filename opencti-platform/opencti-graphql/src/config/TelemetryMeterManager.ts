import { MeterProvider } from '@opentelemetry/sdk-metrics';
import type { Histogram, ObservableResult } from '@opentelemetry/api-metrics';
import { ValueType } from '@opentelemetry/api';

export const TELEMETRY_SERVICE_NAME = 'opencti-telemetry';

export class TelemetryMeterManager {
  meterProvider: MeterProvider;

  private isEEActivated = 0;

  private EEActivationDate: string | undefined = undefined;

  private instancesCount = 0;

  private activUsersHistogram: Histogram | null = null;

  private activUsersCount = 0;

  constructor(meterProvider: MeterProvider) {
    this.meterProvider = meterProvider;
  }

  setIsEEActivated(EE: number) {
    this.isEEActivated = EE;
  }

  setEEActivationDate(date: string | null | undefined) {
    this.EEActivationDate = date ?? undefined;
  }

  setInstancesCount(n: number) {
    this.instancesCount = n;
  }

  setActivUsersHistogram(activUsersCount: number) {
    this.activUsersHistogram?.record(activUsersCount);
  }

  setActivUsersCount(n: number) {
    this.activUsersCount = n;
  }

  registerFiligranTelemetry() {
    const meter = this.meterProvider.getMeter(TELEMETRY_SERVICE_NAME);
    // - Histogram - //
    // number of active users
    // this.activUsersHistogram = meter.createHistogram(
    //   'opencti_activUsersCount',
    //   { description: 'Number of users activ in a session within the last hour',
    //     unit: 'count',
    //     valueType: ValueType.INT,
    //   }
    // );
    // - Gauges - //
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
      observableResult.observe(this.isEEActivated, { EEActivationDate: this.EEActivationDate });
    });
  }
}
