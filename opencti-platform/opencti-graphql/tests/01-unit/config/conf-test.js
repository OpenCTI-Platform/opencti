import nconf from '../../../src/config/conf';

test('default configuration keys must exists', () => {
  const FROM_START = 0;
  const UNTIL_END = 100000000000000;
  const t1 = new Date(FROM_START);
  const t2 = new Date(UNTIL_END);
  const nodeEnv = nconf.get('node_env');
  expect(nodeEnv).toEqual('test');
  // App
  expect(nconf.get('app:port')).toEqual(4000);
  expect(nconf.get('app:logs')).toEqual('./logs');
  // Db
  expect(nconf.get('grakn:hostname')).toBeDefined();
});
