import { afterEach, describe, expect, it, vi } from 'vitest';
import { logApp } from '../../src/config/conf';
import * as httpConfig from '../../src/http/httpConfig';
import { checkHttpSecurity } from '../../src/initialization';

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
    const warn = vi.spyOn(logApp, 'warn').mockImplementation(() => {});

    // When
    checkHttpSecurity();

    // Then
    expect(warn).not.toHaveBeenCalled();
  });
});
