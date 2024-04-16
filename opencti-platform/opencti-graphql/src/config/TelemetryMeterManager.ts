import { MeterProvider } from '@opentelemetry/sdk-metrics';
import type { ObservableResult } from '@opentelemetry/api-metrics';

export const TELEMETRY_SERVICE_NAME = 'opencti-telemetry';

export class TelemetryMeterManager {
  meterProvider: MeterProvider;

  private version = '0';

  private language = 'auto';

  private isEEActivated = 0;

  private EEActivationDate = undefined as string | undefined;

  private numberOfInstances = 0;

  private activUsers = [] as {
    user_id: string, // user id
    lastActivSessionFoundDate: number, // last date when a session was found for the user
  }[];

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

  setActivUsers(activUsersInput: string[], timestamp: number) {
    const newActivUsers = activUsersInput
      .filter((userId) => !this.activUsers.map((n) => n.user_id).includes((userId))) // activ users that were not registered in this.activUsers
      .map((userId) => ({ user_id: userId, lastActivSessionFoundDate: timestamp }));
    const updatedActivUsers = this.activUsers
      .map((activUser) => (activUsersInput.includes(activUser.user_id)
        ? { user_id: activUser.user_id, lastActivSessionFoundDate: timestamp } // update timestamp
        : activUser)) // keep registered user
      .concat(newActivUsers);
    this.activUsers = updatedActivUsers;
  }

  registerFiligranTelemetry() {
    const meter = this.meterProvider.getMeter(TELEMETRY_SERVICE_NAME);
    // - Gauges - //
    // number of instances
    const numberOfInstancesGauge = meter.createObservableGauge('opencti_numberOfInstances');
    numberOfInstancesGauge.addCallback((observableResult: ObservableResult) => {
      observableResult.observe(this.numberOfInstances);
    });
    // number of activ users
    const activUsersGauge = meter.createObservableGauge(
      'opencti_numberOfActivUsers',
      { description: 'Number of users activ in a session within the last hour' }
    );
    activUsersGauge.addCallback((observableResult: ObservableResult) => {
      observableResult.observe(this.activUsers.length);
    });
    // is EE activated
    const isEEActivatedGauge = meter.createObservableGauge('opencti_isEEActivated');
    isEEActivatedGauge.addCallback((observableResult: ObservableResult) => {
      observableResult.observe(this.isEEActivated, { EEActivationDate: this.EEActivationDate });
    });
  }
}
