import { describe, expect, it } from 'vitest';
import { platformBuildVersion } from '../../../src/config/conf-utils';

describe('platformBuildVersion', () => {
  it('should keep the release version without a build commit', () => {
    expect(platformBuildVersion('7.261119.0', undefined)).toBe('7.261119.0');
    expect(platformBuildVersion('7.261119.0', '')).toBe('7.261119.0');
    expect(platformBuildVersion('7.261119.0', '   ')).toBe('7.261119.0');
  });

  it('should suffix the short commit of a rolling build', () => {
    expect(platformBuildVersion('7.261119.0', '32226a6f0b3c4e5d6a7b8c9d0e1f2a3b4c5d6e7f')).toBe('7.261119.0-dev.32226a6');
    expect(platformBuildVersion('7.261119.0', ' 32226A6 ')).toBe('7.261119.0-dev.32226a6');
  });

  it('should ignore a value that is not a commit', () => {
    expect(platformBuildVersion('7.261119.0', 'rolling')).toBe('7.261119.0');
    expect(platformBuildVersion('7.261119.0', 'abc')).toBe('7.261119.0');
    expect(platformBuildVersion('7.261119.0', '7.261120.0')).toBe('7.261119.0');
  });
});
