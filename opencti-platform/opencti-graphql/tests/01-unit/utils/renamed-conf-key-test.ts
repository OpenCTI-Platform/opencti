import { afterEach, describe, expect, it, vi } from 'vitest';
import nconf from 'nconf';
import conf, { isConfKeyDefined, resolveRenamedConfKey } from '../../../src/config/conf';

// Real nconf stores, built like conf.js: environment, command line, configuration file, default.json
const buildStores = (env: Record<string, string>, file: Record<string, unknown>, defaults: Record<string, unknown>) => {
  // The CI runs the unit tests with S3__* / MINIO__* variables set: hide them
  Object.keys(process.env).filter((name) => /^(s3|minio)__/i.test(name)).forEach((name) => vi.stubEnv(name, undefined));
  Object.entries(env).forEach(([name, value]) => vi.stubEnv(name, value));
  const provider = new nconf.Provider();
  provider.env({ separator: '__', lowerCase: true, parseValues: true, match: /^(s3|minio)__/ }); // matched after lowerCase
  provider.argv();
  provider.add('test', { type: 'memory' });
  provider.add('default', { type: 'memory' });
  Object.entries(file).forEach(([key, value]) => provider.stores.test.set(key, value));
  Object.entries(defaults).forEach(([key, value]) => provider.stores.default.set(key, value));
  return provider.stores;
};

describe('Renamed configuration keys', () => {
  afterEach(() => {
    vi.unstubAllEnvs();
  });
  const defaults = { 's3:endpoint': 'localhost', 's3:port': 9000, 's3:access_key': 'ChangeMe', 's3:excluded_files': ['.DS_Store'] };

  it('should prefer the new key when both keys are set in a same store', () => {
    const stores = buildStores({ S3__BUCKET_NAME: 'new-bucket', MINIO__BUCKET_NAME: 'old-bucket' }, {}, defaults);
    expect(resolveRenamedConfKey('s3:bucket_name', 'minio:bucket_name', stores)).toBe('s3:bucket_name');
  });
  it('should use the former key when it is set in a store of higher priority', () => {
    const stores = buildStores({ MINIO__PORT: '19000' }, { 's3:port': 9001 }, defaults);
    expect(resolveRenamedConfKey('s3:port', 'minio:port', stores)).toBe('minio:port');
    expect(resolveRenamedConfKey('s3:endpoint', 'minio:endpoint', stores)).toBe('s3:endpoint');
  });
  it('should use the new key when it is set in a store of higher priority', () => {
    const stores = buildStores({ S3__ENDPOINT: 'new-host' }, { 'minio:endpoint': 'old-host', 'minio:port': 9001 }, defaults);
    expect(resolveRenamedConfKey('s3:endpoint', 'minio:endpoint', stores)).toBe('s3:endpoint');
    expect(resolveRenamedConfKey('s3:port', 'minio:port', stores)).toBe('minio:port');
  });
  it('should use the new key when no store sets the former key', () => {
    const stores = buildStores({}, {}, defaults);
    expect(resolveRenamedConfKey('s3:endpoint', 'minio:endpoint', stores)).toBe('s3:endpoint');
    expect(resolveRenamedConfKey('s3:session_token', 'minio:session_token', stores)).toBe('s3:session_token');
  });
  it('should consider empty values as set, like nconf', () => {
    const stores = buildStores({ MINIO__ACCESS_KEY: '', MINIO__EXCLUDED_FILES: '[]' }, { 'minio:endpoint': null }, defaults);
    expect(resolveRenamedConfKey('s3:access_key', 'minio:access_key', stores)).toBe('minio:access_key');
    expect(resolveRenamedConfKey('s3:excluded_files', 'minio:excluded_files', stores)).toBe('minio:excluded_files');
    expect(resolveRenamedConfKey('s3:endpoint', 'minio:endpoint', stores)).toBe('minio:endpoint');
  });
  it('should report a former key as defined when its value is empty', () => {
    const stores = buildStores({ MINIO__ACCESS_KEY: '', MINIO__EXCLUDED_FILES: '[]' }, {}, defaults);
    expect(isConfKeyDefined('minio:access_key', stores)).toBeTruthy();
    expect(isConfKeyDefined('minio:excluded_files', stores)).toBeTruthy();
    expect(isConfKeyDefined('minio:endpoint', stores)).toBeFalsy();
  });
  it('should read the stores of the platform configuration in nconf priority order', () => {
    const names = Object.keys(conf.stores);
    expect(names.slice(0, 2)).toEqual(['env', 'argv']);
    expect(names[names.length - 1]).toBe('default');
    expect(names.length).toBe(4);
  });
  it('should resolve a nested section as a whole', () => {
    const stores = buildStores({ MINIO__CREDENTIALS_PROVIDER__SELECTOR: 'cyberark' }, { 'minio:credentials_provider:cyberark:uri': 'http://vault' }, defaults);
    expect(resolveRenamedConfKey('s3:credentials_provider', 'minio:credentials_provider', stores)).toBe('minio:credentials_provider');
    expect(isConfKeyDefined('minio:credentials_provider:cyberark:uri', stores)).toBeTruthy();
    expect(isConfKeyDefined('s3:credentials_provider', stores)).toBeFalsy();
  });
  it('should resolve a nested section from the store of highest priority across names', () => {
    const stores = buildStores({ MINIO__CREDENTIALS_PROVIDER__SELECTOR: 'cyberark' }, { 's3:credentials_provider:selector': 'https_cert' }, defaults);
    expect(resolveRenamedConfKey('s3:credentials_provider', 'minio:credentials_provider', stores)).toBe('minio:credentials_provider');
  });
});
