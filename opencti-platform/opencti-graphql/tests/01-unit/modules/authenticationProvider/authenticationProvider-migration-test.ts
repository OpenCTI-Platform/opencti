import { describe, expect, it } from 'vitest';
import { isLocalAuthEnabledInEnv } from '../../../../src/modules/authenticationProvider/providers-configuration';

// ==========================================================================
// resolveLocalAuthEnabled
// ==========================================================================

describe('resolveLocalAuthEnabled', () => {
  it('should return true when no local provider is configured', () => {
    expect(isLocalAuthEnabledInEnv({})).toBe(true);
  });

  it('should return true when local provider exists but disabled is not set', () => {
    const providers = { local: { strategy: 'LocalStrategy', config: {} } };
    expect(isLocalAuthEnabledInEnv(providers)).toBe(true);
  });

  it('should return true when local provider disabled is explicitly false', () => {
    const providers = { local: { strategy: 'LocalStrategy', config: { disabled: false } } };
    expect(isLocalAuthEnabledInEnv(providers)).toBe(true);
  });

  it('should return false when local provider disabled is explicitly true', () => {
    const providers = { local: { strategy: 'LocalStrategy', config: { disabled: true } } };
    expect(isLocalAuthEnabledInEnv(providers)).toBe(false);
  });

  it('should return true when local provider has no config property', () => {
    const providers = { local: { strategy: 'LocalStrategy' } };
    expect(isLocalAuthEnabledInEnv(providers)).toBe(true);
  });

  it('should not be affected by other providers being present', () => {
    const providers = {
      oidc: { strategy: 'OpenIDConnectStrategy', config: { disabled: true } },
      local: { strategy: 'LocalStrategy', config: { disabled: false } },
    };
    expect(isLocalAuthEnabledInEnv(providers)).toBe(true);
  });

  it('should return false when local is disabled even if other providers are enabled', () => {
    const providers = {
      oidc: { strategy: 'OpenIDConnectStrategy', config: { disabled: false } },
      local: { strategy: 'LocalStrategy', config: { disabled: true } },
    };
    expect(isLocalAuthEnabledInEnv(providers)).toBe(false);
  });
});
