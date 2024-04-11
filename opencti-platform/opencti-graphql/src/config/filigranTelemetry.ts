import { MeterProvider } from '@opentelemetry/sdk-metrics';
import { LoggerProvider } from '@opentelemetry/sdk-logs';

class FiligranTelemetryManager {
  meterProvider: MeterProvider;

  loggerProvider: LoggerProvider;

  private version = '0';

  private language = 'auto';

  private isEEActivated = false;

  private EEActivationDate = undefined as string | undefined;

  private numberOfInstances = 0;

  private activUsers = [] as {
    user_id: string, // user id
    lastActivSessionFoundDate: number, // last date when a session was found for the user
  }[];

  constructor(meterProvider: MeterProvider, loggerProvider: LoggerProvider) {
    this.meterProvider = meterProvider;
    this.loggerProvider = loggerProvider;
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

  registerMetrics() {
    // TODO
  }

  registerLogs(timestamp: number) {
    const logger = this.loggerProvider.getLogger('opencti-api');
    const logRecord = {
      body: {
        opencti_version: this.version,
        opencti_numberOfActivUsers: this.activUsers.length,
        opencti_language: this.language,
        opencti_isEEActivated: this.isEEActivated,
        opencti_EEActivationDate: this.EEActivationDate,
        opencti_numberOfInstances: this.numberOfInstances,
        timestamp,
      },
    };
    logger.emit(logRecord);
  }

  registerFiligranTelemetry(timestamp: number) {
    this.registerMetrics(); // for metrics
    this.registerLogs(timestamp); // for string
  }
}
export const filigranTelemetryMeterProvider = new MeterProvider({});
export const filigranTelemetryLoggerProvider = new LoggerProvider();
export const filigranTelemetryManager = new FiligranTelemetryManager(filigranTelemetryMeterProvider, filigranTelemetryLoggerProvider);
