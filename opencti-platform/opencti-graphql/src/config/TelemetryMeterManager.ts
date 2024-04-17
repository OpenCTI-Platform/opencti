import { MeterProvider } from '@opentelemetry/sdk-metrics';
import type { ObservableResult } from '@opentelemetry/api-metrics';

export const TELEMETRY_SERVICE_NAME = 'opencti-telemetry';

export class TelemetryMeterManager {
  meterProvider: MeterProvider;

  private version = '0';

  private language = 'auto';

  private isEEActivated = 0;

  private EEActivationDate: string | undefined = undefined;

  private numberOfInstances = 0;

  private activUsers: { user_id: string, lastActivity: number }[] = []; // user activ in the last 24 hours and their last activity timestamp

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
      .map((userId) => ({ user_id: userId, lastActivity: timestamp }));
    const updatedActivUsers = this.activUsers
      .map((activUser) => (activUsersInput.includes(activUser.user_id)
        ? { user_id: activUser.user_id, lastActivity: timestamp } // update timestamp
        : activUser)) // keep registered user
      .concat(newActivUsers);
    const limitDate = timestamp - 86400000; // clear the users not activ in the last 24 hours
    this.activUsers = updatedActivUsers.filter((user) => user.lastActivity >= limitDate);
  }

  registerFiligranTelemetry() {
    const meter = this.meterProvider.getMeter(TELEMETRY_SERVICE_NAME);
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
    // number of users activ in the last 24 hours
    const activUsersGauge = meter.createObservableGauge(
      'opencti_numberOfActivUsers',
      { description: 'number of activ users, i.e. users activ in the last 24 hours' },
    );
    activUsersGauge.addCallback((observableResult: ObservableResult) => {
      observableResult.observe(this.activUsers.length);
    });
  }
}
