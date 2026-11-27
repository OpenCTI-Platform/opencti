import { afterEach, describe, expect, it, vi } from 'vitest';
import conf, { logApp } from '../../src/config/conf';
import * as httpConfig from '../../src/http/httpConfig';
import { checkAuthenticationSecurity, checkHttpSecurity } from '../../src/initialization';

// The migrations are loaded through a glob import that only the build resolves
vi.mock('../../src/database/migration', () => ({ applyMigration: vi.fn(), lastAvailableMigrationTime: vi.fn() }));

describe('checkHttpSecurity', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should warn at startup when the HTTP switch is off', () => {
    // Given
    vi.spyOn(httpConfig, 'isHttpSecureByDefault').mockReturnValue(false);
    const warn = vi.spyOn(logApp, 'warn').mockImplementation(() => {});

    // When
    checkHttpSecurity();

    // Then
    expect(warn).toHaveBeenCalledWith(expect.stringContaining('app:http:secure_by_default=false'));
  });

  it('should not warn when the HTTP switch is on', () => {
    // Given
    vi.spyOn(httpConfig, 'isHttpSecureByDefault').mockReturnValue(true);
    vi.spyOn(httpConfig, 'getInvalidHttpMaxRedirects').mockReturnValue(undefined);
    const warn = vi.spyOn(logApp, 'warn').mockImplementation(() => {});

    // When
    checkHttpSecurity();

    // Then
    expect(warn).not.toHaveBeenCalled();
  });

  it('should warn at startup when the number of redirects is invalid', () => {
    // Given
    vi.spyOn(httpConfig, 'isHttpSecureByDefault').mockReturnValue(true);
    vi.spyOn(httpConfig, 'getInvalidHttpMaxRedirects').mockReturnValue('3x');
    vi.spyOn(httpConfig, 'getHttpMaxRedirects').mockReturnValue(5);
    const warn = vi.spyOn(logApp, 'warn').mockImplementation(() => {});

    // When
    checkHttpSecurity();

    // Then
    expect(warn).toHaveBeenCalledWith(expect.stringContaining('app:http:max_redirects'), { value: '3x', default: 5 });
  });
});

describe('checkAuthenticationSecurity', () => {
  afterEach(() => {
    conf.clear('app:authentication:secure_by_default');
    vi.restoreAllMocks();
  });

  it('should warn at startup when the authentication switch is off', () => {
    // Given
    const warn = vi.spyOn(logApp, 'warn').mockImplementation(() => {});

    // When
    checkAuthenticationSecurity();

    // Then
    expect(warn).toHaveBeenCalledWith(expect.stringContaining('app:authentication:secure_by_default=false'));
  });

  it('should not warn when the authentication switch is on', () => {
    // Given
    conf.set('app:authentication:secure_by_default', true);
    const warn = vi.spyOn(logApp, 'warn').mockImplementation(() => {});

    // When
    checkAuthenticationSecurity();

    // Then
    expect(warn).not.toHaveBeenCalled();
  });
});
