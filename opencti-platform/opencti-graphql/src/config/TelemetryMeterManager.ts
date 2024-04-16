import { MeterProvider } from '@opentelemetry/sdk-metrics';
import type { ObservableResult } from '@opentelemetry/api-metrics';
import type { Histogram } from '@opentelemetry/api';

export const TELEMETRY_SERVICE_NAME = 'opencti-telemetry';

export class TelemetryMeterManager {
  meterProvider: MeterProvider;

  private version = '0';

  private language = 'auto';

  private isEEActivated = 0;

  private EEActivationDate: string | undefined = undefined;

  private numberOfInstances = 0;

  private activUsersHistogram: Histogram | null = null;

  constructor(meterProvider: MeterProvider) {
    this.meterProvider = meterProvider;
  }

  setLanguage(lang: string) {
    this.language = lang;
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

  setActivUsersInHistogram(activUsersInput: string[]) {
    this.activUsersHistogram?.record(activUsersInput.length);
  }

  registerFiligranTelemetry() {
    const meter = this.meterProvider.getMeter(TELEMETRY_SERVICE_NAME);
    // - Histogram - //
    // number of activ users
    this.activUsersHistogram = meter.createHistogram(
      'opencti_numberOfActivUsers',
      { description: 'Number of users activ in a session within the last hour' }
    );
    // - Gauges - //
    // number of instances
    const numberOfInstancesGauge = meter.createObservableGauge('opencti_numberOfInstances');
    numberOfInstancesGauge.addCallback((observableResult: ObservableResult) => {
      observableResult.observe(this.numberOfInstances);
    });
    // is EE activated
    const isEEActivatedGauge = meter.createObservableGauge('opencti_isEEActivated');
    isEEActivatedGauge.addCallback((observableResult: ObservableResult) => {
      observableResult.observe(this.isEEActivated, { EEActivationDate: this.EEActivationDate });
    });
  }
}
