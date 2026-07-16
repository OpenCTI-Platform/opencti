import nconf from 'nconf';

import { booleanConf, logApp } from './config/conf';

const isPyroscopeEnable = booleanConf('app:telemetry:pyroscope:enabled', false);
if (isPyroscopeEnable) {
  const { default: pyroscope } = await import('@pyroscope/nodejs');
  const node = nconf.get('app:telemetry:pyroscope:identifier') ?? 'opencti';
  const exporter = nconf.get('app:telemetry:pyroscope:exporter');
  try {
    const sourceMapper = await pyroscope.SourceMapper.create(['.']);
    pyroscope.init({ serverAddress: exporter, appName: node, sourceMapper });
    pyroscope.start();
    logApp.info('[OPENCTI] Pyroscope plugin successfully loaded.');
  } catch (err) {
    logApp.error('[OPENCTI] Error loading Pyroscope', { cause: err });
  }
}
