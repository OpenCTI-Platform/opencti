import { describe, expect, it } from 'vitest';
import { canDeployConnector } from './isDeployableConnector';

describe('canDeployConnector', () => {
  it('returns true only for supported connectors', () => {
    expect(canDeployConnector({ manager_supported: true })).toBe(true);
    expect(canDeployConnector({ manager_supported: false })).toBe(false);
    expect(canDeployConnector({ manager_supported: undefined })).toBe(false);
    expect(canDeployConnector(null)).toBe(false);
    expect(canDeployConnector(undefined)).toBe(false);
  });
});
