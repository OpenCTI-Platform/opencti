import nconf from '../conf';

test('default configuration keys must exists', () => {
  const nodeEnv = nconf.get('NODE_ENV');
  expect(nodeEnv).toEqual('test');
  // App
  expect(nconf.get('app:port')).toEqual(4000);
  expect(nconf.get('app:logs')).toEqual('./logs');
  // Db
  expect(nconf.get('db:uri')).toBeDefined();
  expect(nconf.get('db:user')).toBeDefined();
  expect(nconf.get('db:password')).toBeDefined();
  // Jwt
  expect(nconf.get('app:secret')).toBeDefined();
});
