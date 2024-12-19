import * as Pyroscope from '@pyroscope/nodejs';
import nconf from 'nconf';
import { booleanConf, logApp } from './config/conf';

const isPyroscopeEnable = booleanConf('app:telemetry:pyroscope:enabled', false);
if (isPyroscopeEnable) {
  try {
    const node = nconf.get('app:telemetry:pyroscope:node');
    const exporter = nconf.get('app:telemetry:pyroscope:exporter');
    Pyroscope.init({ serverAddress: exporter, appName: node });
    Pyroscope.start();
  } catch (err) {
    logApp.error('[OPENCTI] Error loading Pyroscope', { err });
  }
}
