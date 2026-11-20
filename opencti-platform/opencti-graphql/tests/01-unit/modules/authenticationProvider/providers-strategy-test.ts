import { afterEach, describe, expect, it } from 'vitest';
import passport from 'passport';
import { Strategy as LocalStrategy } from 'passport-local';
import { Strategy as SamlStrategy } from '@node-saml/passport-saml';
import { findProviderStrategy, isSamlStrategy } from '../../../../src/modules/authenticationProvider/providers-strategy';

const TEST_PROVIDER = 'providers-strategy-test';

const buildSamlStrategy = () => new SamlStrategy(
  {
    name: TEST_PROVIDER,
    callbackUrl: 'http://localhost:4000/auth/saml/callback',
    entryPoint: 'https://idp.example.com/sso',
    issuer: 'opencti-test',
    idpCert: 'not-a-real-certificate',
  },
  () => {},
  () => {},
);

describe('providers-strategy', () => {
  afterEach(() => {
    if (findProviderStrategy(TEST_PROVIDER)) {
      passport.unuse(TEST_PROVIDER);
    }
  });

  it('finds the strategy registered under a provider identifier', () => {
    const strategy = new LocalStrategy(() => {});
    passport.use(TEST_PROVIDER, strategy);
    expect(findProviderStrategy(TEST_PROVIDER)).toBe(strategy);
  });

  it('returns undefined for an unknown or unregistered provider', () => {
    expect(findProviderStrategy('unknown-provider')).toBeUndefined();
    passport.use(TEST_PROVIDER, new LocalStrategy(() => {}));
    passport.unuse(TEST_PROVIDER);
    expect(findProviderStrategy(TEST_PROVIDER)).toBeUndefined();
  });

  it('detects SAML strategies', () => {
    expect(isSamlStrategy(buildSamlStrategy())).toBe(true);
  });

  it('does not take other strategies or missing values for SAML', () => {
    expect(isSamlStrategy(new LocalStrategy(() => {}))).toBe(false);
    expect(isSamlStrategy(undefined)).toBe(false);
    expect(isSamlStrategy({ _saml: {} })).toBe(false);
  });
});
