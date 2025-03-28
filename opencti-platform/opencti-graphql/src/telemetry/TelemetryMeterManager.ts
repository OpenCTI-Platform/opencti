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

  // Number of active connectors
  activeConnectorsCount = 0;

  disseminationCount = 0;

  // Number of active drafts
  draftCount = 0;

  // Number of active workbenches
  workbenchCount = 0;

  // Number of NLQ query call
  nlqQueryCount = 0;

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

  setUsersCount(n: number) {
    this.usersCount = n;
  }

  setActiveConnectorsCount(n: number) {
    this.activeConnectorsCount = n;
  }

  setDisseminationCount(n: number) {
    this.disseminationCount = n;
  }

  setDraftCount(n: number) {
    this.draftCount = n;
  }

  setWorkbenchCount(n: number) {
    this.workbenchCount = n;
  }

  setNlqQueryCount(n: number) {
    this.nlqQueryCount = n;
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
    this.registerGauge('total_instances_count', 'cluster number of instances', 'instancesCount');
    this.registerGauge('active_connectors_count', 'number of active connectors', 'activeConnectorsCount');
    this.registerGauge('is_enterprise_edition', 'enterprise Edition is activated', 'isEEActivated', { unit: 'boolean' });
    this.registerGauge('call_dissemination', 'dissemination feature usage', 'disseminationCount');
    this.registerGauge('active_drafts_count', 'number of active drafts', 'draftCount');
    this.registerGauge('active_workbenches_count', 'number of active workbenches', 'workbenchCount');
    this.registerGauge('call_nlq', 'NLQ feature usage', 'nlqQueryCount');
  }
}
