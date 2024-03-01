import { describe, expect, it } from 'vitest';
import { isCompatibleVersionWithMinimal } from '../../../src/utils/version';

describe('Version utils Tests', () => {
  it('should test compatible version with minimal', () => {
    expect(isCompatibleVersionWithMinimal('6.0.0', '5.12.16')).toBeTruthy();
    expect(isCompatibleVersionWithMinimal('5.12.16', '5.12.16')).toBeTruthy();
    expect(isCompatibleVersionWithMinimal('5.12.17', '5.12.16')).toBeTruthy();
    expect(isCompatibleVersionWithMinimal('5.13.1', '5.12.16')).toBeTruthy();
    expect(isCompatibleVersionWithMinimal('5.11.16', '5.12.16')).toBeFalsy();
    expect(isCompatibleVersionWithMinimal('5.12.15', '5.12.16')).toBeFalsy();
    expect(isCompatibleVersionWithMinimal('5.0.0', '5.12.16')).toBeFalsy();
    expect(isCompatibleVersionWithMinimal('4.12.16', '5.12.16')).toBeFalsy();
  });
});
