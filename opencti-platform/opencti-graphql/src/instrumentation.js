import nconf from 'nconf';
import { booleanConf, logApp } from './config/conf';

const isPyroscopeEnable = booleanConf('app:telemetry:pyroscope:enabled', false);
if (isPyroscopeEnable) {
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires,global-require
    const Pyroscope = require('@pyroscope/nodejs');
    const node = nconf.get('app:telemetry:pyroscope:identifier') ?? 'opencti';
    const exporter = nconf.get('app:telemetry:pyroscope:exporter');
    Pyroscope.init({ serverAddress: exporter, appName: node });
    Pyroscope.start();
    logApp.info('[OPENCTI] Pyroscope plugin successfully loaded.');
  } catch (err) {
    logApp.error('[OPENCTI] Error loading Pyroscope', { cause: err.message });
  }
}
