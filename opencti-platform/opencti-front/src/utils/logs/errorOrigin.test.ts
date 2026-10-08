import { describe, expect, it } from 'vitest';
import { APP_MODULE, classifyFrontendError, resolveRouteModule, toAppModule, toErrorDependency, toErrorOrigin } from './errorOrigin';

const relayError = (res: Record<string, unknown>) => Object.assign(new Error('Relay request failed'), { res });

describe('frontend error origin (RFC 0006)', () => {
  it('should classify a crash of the UI code as code', () => {
    expect(classifyFrontendError(new TypeError('value.split is not a function'))).toEqual({ origin: 'code' });
    expect(classifyFrontendError('a thrown string')).toEqual({ origin: 'code' });
    expect(classifyFrontendError(undefined)).toEqual({ origin: 'code' });
  });

  it('should classify a chunk that failed to load as an assets failure', () => {
    expect(classifyFrontendError(new TypeError('Failed to fetch dynamically imported module: https://opencti/static/Integrations-x1.js')))
      .toEqual({ origin: 'infra', dependency: 'assets' });
    expect(classifyFrontendError(new TypeError('Importing a module script failed.'))).toEqual({ origin: 'infra', dependency: 'assets' });
  });

  it('should classify a request that never got a response as an API failure', () => {
    expect(classifyFrontendError(new TypeError('Failed to fetch'))).toEqual({ origin: 'infra', dependency: 'api' });
    expect(classifyFrontendError(new TypeError('NetworkError when attempting to fetch resource.'))).toEqual({ origin: 'infra', dependency: 'api' });
    expect(classifyFrontendError(relayError({ status: 503 }))).toEqual({ origin: 'infra', dependency: 'api' });
  });

  it('should follow the backend classification of the errors the API returned', () => {
    expect(classifyFrontendError(relayError({ status: 200, errors: [{ extensions: { origin: 'input' } }] }))).toEqual({ origin: 'input' });
    expect(classifyFrontendError(relayError({ status: 200, errors: [{ extensions: { origin: 'code' } }] }))).toEqual({ origin: 'infra', dependency: 'api' });
    expect(classifyFrontendError({ data: { res: { errors: [{ extensions: { origin: 'input' } }] } } })).toEqual({ origin: 'input' });
  });

  it('should treat a mix of rejected input and failures as an API failure', () => {
    const mixed = relayError({ errors: [{ extensions: { origin: 'input' } }, { extensions: { origin: 'infra' } }] });
    expect(classifyFrontendError(mixed)).toEqual({ origin: 'infra', dependency: 'api' });
  });
});

describe('frontend entry module', () => {
  it('should resolve the module of the page', () => {
    expect(resolveRouteModule('/dashboard/integrations/available')).toBe(APP_MODULE.CATALOG);
    expect(resolveRouteModule('/dashboard/integrations/catalog/opencti-mitre')).toBe(APP_MODULE.CATALOG);
    expect(resolveRouteModule('/dashboard/integrations/deployed')).toBe(APP_MODULE.CONNECTOR);
  });

  it('should match under a base path', () => {
    expect(resolveRouteModule('/opencti/dashboard/integrations/available')).toBe(APP_MODULE.CATALOG);
  });

  it('should not match a page outside any module, or a prefix of a longer segment', () => {
    expect(resolveRouteModule('/dashboard/analyses/reports')).toBeUndefined();
    expect(resolveRouteModule('/dashboard/integrations/available-soon')).toBeUndefined();
    expect(resolveRouteModule('/public/dashboard')).toBeUndefined();
  });
});

describe('enum guards', () => {
  it('should only let through the values of the GraphQL enums', () => {
    expect(toAppModule('catalog')).toBe('catalog');
    expect(toAppModule('playbook')).toBeNull();
    expect(toErrorOrigin('infra')).toBe('infra');
    expect(toErrorOrigin('unknown')).toBeNull();
    expect(toErrorDependency('assets')).toBe('assets');
    expect(toErrorDependency(undefined)).toBeNull();
  });
});
