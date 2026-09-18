import { describe, expect, it } from 'vitest';
import { canDeployConnector } from './isDeployableConnector';

describe('canDeployConnector', () => {
  it('returns true only for supported connectors when no platform version is provided', () => {
    expect(canDeployConnector({ manager_supported: true })).toBe(true);
    expect(canDeployConnector({ manager_supported: false })).toBe(false);
    expect(canDeployConnector({ manager_supported: undefined })).toBe(false);
    expect(canDeployConnector(null)).toBe(false);
    expect(canDeployConnector(undefined)).toBe(false);
  });

  it('returns false for a managed connector when no compatible version exists', () => {
    expect(canDeployConnector({
      manager_supported: true,
      versions: [
        { version: '7.260950.0', min_platform_version: '7.260950.0' },
      ],
    }, '7.260901.0')).toBe(false);
  });

  it('returns true for a managed connector when at least one compatible version exists', () => {
    expect(canDeployConnector({
      manager_supported: true,
      versions: [
        { version: '7.260950.0', min_platform_version: '7.260950.0' },
        { version: '7.260828.0', min_platform_version: '7.260828.0' },
      ],
    }, '7.260901.0')).toBe(true);
  });

  it('falls back to the connector support_version when no versions list is present', () => {
    expect(canDeployConnector({
      manager_supported: true,
      container_version: '7.260901.0',
      support_version: '7.260901.0',
    }, '7.260901.0')).toBe(true);
    expect(canDeployConnector({
      manager_supported: true,
      container_version: '7.260950.0',
      support_version: '7.260950.0',
    }, '7.260901.0')).toBe(false);
  });
});
