import { describe, it, expect } from 'vitest';
import { ALL_RESULTS_VALUE, toResultId } from './securityCoverageResultScope';

describe('securityCoverageResultScope', () => {
  it('maps the all-results value to no result', () => {
    expect(toResultId(ALL_RESULTS_VALUE)).toBeNull();
    expect(toResultId('scr-paris')).toBe('scr-paris');
  });
});
