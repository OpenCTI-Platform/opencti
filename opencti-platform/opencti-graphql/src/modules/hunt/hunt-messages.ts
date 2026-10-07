/**
 * Sentences of the hunt readiness, the same in the platform errors and in the user interface: the English sentence is
 * the translation key of the front end, its {placeholders} filled with the values the platform sends along.
 */
export const HUNT_MESSAGES = {
  logicTelemetryMissing: 'Add a Sigma rule or a native query',
  logicInfrastructureMissing: 'Add a native query for the internet platform',
  logicIndicatorsMissing: 'Add the indicators or observables to look for',
  logicIndicatorsEmpty: 'None of the indicators and observables of this hunt has a value a lookup can search: add values or other indicators',
  sigmaInvalid: 'Invalid Sigma rule: {errors}',
  sigmaValid: 'Valid Sigma rule',
  nativeQueries: 'Native query for {platforms}',
  iocCount: '{count} values to look for',
  iocTruncated: 'Only the first {max} values are looked for: narrow the list',
  iocRestricted: '{count} indicators or observables are more restricted than the hunt and are left out: raise the markings of the hunt',
  iocUnsupported: '{count} indicators have no value a lookup can search: a pattern in another language or without an equality comparison',
  connectorMissing: 'No hunt connector can run it on the platforms of its scope: deploy a hunt connector or widen the scope',
  connectorIndicatorsMissing: 'No hunt connector of its scope supports indicator lookups: deploy one that does, such as the Splunk hunt connector',
  connectorInternetMissing: 'No internet hunt connector is deployed: deploy the infrastructure tracker connector',
  connectorReady: '{connectors} can run it',
  connectorUnreachable: '{connectors} has not answered recently: runs wait in the queue until it is back',
  scheduleManual: 'Manual: it runs when you click Run now',
  scheduleCron: 'Runs on its schedule: {schedule}',
  scheduleStanding: 'Standing: it runs when a change matches its trigger filters',
  schedulePir: 'Runs when a PIR flags one of its targets',
  scheduleInvalid: 'Invalid schedule: {error}',
  scheduleEnterprise: 'Scheduled, standing and PIR-activated hunts need the Enterprise Edition: set the schedule to manual',
  scopeAll: 'Runs on every hunt-capable security platform',
  scopePlatforms: 'Runs on {platforms}',
  scopeEmpty: 'The scope matches no security platform: edit the scope',
  scopeInternet: 'Runs on the internet hunt connectors',
  draftWorkspace: 'In a draft workspace: the hunt runs once the draft is validated',
  queueConnectorDeleted: 'The hunt connector of this run was deleted: the run is cancelled at the next pass of the hunt manager',
  queueConnectorOffline: '{connector} has not answered recently: the run starts once it is back',
  queueConnectorBusy: '{connector} already runs {count} hunts, its limit: the run starts when one of them ends',
  queueConnectorQuota: '{connector} reached its daily quota of {count} runs: the run starts tomorrow',
  queueSent: 'Sent to {connector}: waiting for the connector to start it',
  queueNextDispatch: 'Waiting for the next dispatch of the hunt manager',
  runCancelledHuntDeleted: 'The hunt of this run was deleted',
  runCancelledConnectorDeleted: 'The hunt connector of this run was deleted',
  runCancelledConnectorRebound: 'The hunt connector of this run now executes against another security platform',
  runFailedTranslation: '{connector} cannot translate the hunt logic for its platform: edit the Sigma rule or add a native query, the run is not retried',
  runFailedRejected: '{connector} refuses this run the same way at every attempt: fix the hunt logic, the run is not retried',
  translationReady: '{connector} translated the hunt logic',
  translationChecking: '{connector} is checking the translation of the hunt logic',
  translationFailed: '{connector} cannot translate the hunt logic: {error}',
} as const;

export type HuntMessageValues = Record<string, string | number>;

export const renderHuntMessage = (template: string, values: HuntMessageValues = {}) => {
  return template.replace(/\{(\w+)\}/g, (placeholder, name: string) => (values[name] !== undefined ? String(values[name]) : placeholder));
};

export interface HuntMessage {
  template: string;
  values: { name: string; value: string }[];
  message: string;
}

/** A sentence as the API serves it: its template, translated by the user interface, its values and its rendering. */
export const huntMessage = (template: string, values: HuntMessageValues = {}): HuntMessage => ({
  template,
  values: Object.entries(values).map(([name, value]) => ({ name, value: String(value) })),
  message: renderHuntMessage(template, values),
});

/** At most three names, then the count of the others. */
export const listNames = (names: string[]) => {
  const unique = Array.from(new Set(names));
  if (unique.length <= 3) {
    return unique.join(', ');
  }
  return `${unique.slice(0, 3).join(', ')} +${unique.length - 3}`;
};
