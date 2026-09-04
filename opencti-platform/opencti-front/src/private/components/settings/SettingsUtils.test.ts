import { describe, expect, it } from 'vitest';
import { formatOpenCTIVersion } from './SettingsUtils';

describe('formatOpenCTIVersion', () => {
  it('should append the build commit when present', () => {
    expect(formatOpenCTIVersion('7.0.0', 'abcdef0')).toBe('7.0.0 (abcdef0)');
  });

  it('should only display the version when the build commit is absent', () => {
    expect(formatOpenCTIVersion('7.0.0', null)).toBe('7.0.0');
  });
});
