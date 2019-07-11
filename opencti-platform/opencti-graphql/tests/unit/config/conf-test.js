import nconf from '../../../src/config/conf';

test('default configuration keys must exists', () => {
  const nodeEnv = nconf.get('node_env');
  expect(nodeEnv).toEqual('test');
  // App
  expect(nconf.get('app:port')).toEqual(4000);
  expect(nconf.get('app:logs')).toEqual('./logs');
  // Db
  expect(nconf.get('grakn:hostname')).toBeDefined();
});
