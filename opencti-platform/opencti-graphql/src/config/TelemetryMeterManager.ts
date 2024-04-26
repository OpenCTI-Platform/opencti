import { MeterProvider } from '@opentelemetry/sdk-metrics';
import type { Histogram, ObservableResult } from '@opentelemetry/api-metrics';
import { ValueType } from '@opentelemetry/api';

export const TELEMETRY_SERVICE_NAME = 'opencti-telemetry';

export class TelemetryMeterManager {
  meterProvider: MeterProvider;

  private isEEActivated = 0;

  private EEActivationDate: string | undefined = undefined;

  private numberOfInstances = 0;

  private activUsersHistogram: Histogram | null = null;

  constructor(meterProvider: MeterProvider) {
    this.meterProvider = meterProvider;
  }

  setIsEEActivated(EE: number) {
    this.isEEActivated = EE;
  }

  setEEActivationDate(date: string | null | undefined) {
    this.EEActivationDate = date ?? undefined;
  }

  setNumberOfInstances(n: number) {
    this.numberOfInstances = n;
  }

  setActivUsersHistogram(activUsersNumber: number) {
    this.activUsersHistogram?.record(activUsersNumber);
  }

  registerFiligranTelemetry() {
    const meter = this.meterProvider.getMeter(TELEMETRY_SERVICE_NAME);
    // - Histogram - //
    // number of activ users
    this.activUsersHistogram = meter.createHistogram(
      'opencti_numberOfActivUsers',
      { description: 'Number of users activ in a session within the last hour',
        unit: 'count',
        valueType: ValueType.INT,
      }
    );
    // - Gauges - //
    // number of instances
    const numberOfInstancesGauge = meter.createObservableGauge(
      'opencti_numberOfInstances',
      { description: 'number of instances', unit: 'count', valueType: ValueType.INT },
    );
    numberOfInstancesGauge.addCallback((observableResult: ObservableResult) => {
      observableResult.observe(this.numberOfInstances);
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
