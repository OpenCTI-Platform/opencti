import nconf from 'nconf';

import { SourceMapper } from '@datadog/pprof';
import { booleanConf, logApp } from './config/conf';

const isPyroscopeEnable = booleanConf('app:telemetry:pyroscope:enabled', false);
if (isPyroscopeEnable) {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const Pyroscope = require('@pyroscope/nodejs');
  const node = nconf.get('app:telemetry:pyroscope:identifier') ?? 'opencti';
  const exporter = nconf.get('app:telemetry:pyroscope:exporter');
  SourceMapper.create(['.']).then((sourceMapper) => {
    Pyroscope.init({ serverAddress: exporter, appName: node, sourceMapper });
    Pyroscope.start();
  }).then(() => {
    logApp.info('[OPENCTI] Pyroscope plugin successfully loaded.');
  }).catch((err) => {
    logApp.error('[OPENCTI] Error loading Pyroscope', { cause: err });
  });
}
