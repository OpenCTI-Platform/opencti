import { MeterProvider } from '@opentelemetry/sdk-metrics';
import type { ObservableResult } from '@opentelemetry/api-metrics';

export class TelemetryMeterManager {
  meterProvider: MeterProvider;

  private version = '0';

  private language = 'auto';

  private isEEActivated = false;

  private EEActivationDate = undefined as string | undefined;

  private numberOfInstances = 0;

  private activUsers = [] as {
    user_id: string, // user id
    lastActivSessionFoundDate: number, // last date when a session was found for the user
  }[];

  constructor(meterProvider: MeterProvider) {
    this.meterProvider = meterProvider;
  }

  setVersion(val: string) {
    this.version = val;
  }

  setLanguage(lang: string) {
    this.language = lang;
  }

  setIsEEActivated(EE: boolean) {
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
    const meter = this.meterProvider.getMeter('opencti');
    // - Gauges
    const latencyGauge = meter.createObservableGauge('opencti_numberOfInstances');
    latencyGauge.addCallback((observableResult: ObservableResult) => {
      observableResult.observe(this.numberOfInstances);
    });
  }
}
