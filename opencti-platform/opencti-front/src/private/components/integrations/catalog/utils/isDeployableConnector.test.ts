import { describe, expect, it } from 'vitest';
import { canDeployConnector } from './isDeployableConnector';

describe('canDeployConnector', () => {
  it('returns true only for supported connectors when no backend compatibility is provided', () => {
    expect(canDeployConnector({ manager_supported: true })).toBe(true);
    expect(canDeployConnector({ manager_supported: false })).toBe(false);
    expect(canDeployConnector({ manager_supported: undefined })).toBe(false);
    expect(canDeployConnector(null)).toBe(false);
    expect(canDeployConnector(undefined)).toBe(false);
  });

  it('returns false for a managed connector when backend compatibility marks it incompatible', () => {
    expect(canDeployConnector({
      manager_supported: true,
      compatibility: {
        is_compatible: false,
        latest_compatible_version: null,
        minimum_platform_version: '7.260950.0',
      },
    })).toBe(false);
  });

  it('returns true for a managed connector when backend compatibility marks it compatible', () => {
    expect(canDeployConnector({
      manager_supported: true,
      compatibility: {
        is_compatible: true,
        latest_compatible_version: '7.260828.0',
        minimum_platform_version: '7.260828.0',
      },
    })).toBe(true);
  });

  it('falls back to client-side version checks when compatibility is absent', () => {
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
