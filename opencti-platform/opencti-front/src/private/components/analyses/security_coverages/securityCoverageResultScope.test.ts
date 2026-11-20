import { describe, it, expect } from 'vitest';
import { ALL_RESULTS_VALUE, resolveSelectedResult, toResultId } from './securityCoverageResultScope';

describe('securityCoverageResultScope', () => {
  const paris = { id: 'scr-paris', name: 'OAEV Paris', external_uri: 'https://paris' };
  const lyon = { id: 'scr-lyon', name: 'OAEV Lyon', external_uri: 'https://lyon' };

  it('maps the all-results value to no result', () => {
    expect(toResultId(ALL_RESULTS_VALUE)).toBeNull();
    expect(toResultId('scr-paris')).toBe('scr-paris');
  });
  it('resolves the selected result, or null when it is gone', () => {
    expect(resolveSelectedResult([paris, lyon], 'scr-lyon')).toBe(lyon);
    expect(resolveSelectedResult([paris], 'scr-lyon')).toBeNull();
    expect(resolveSelectedResult([paris], null)).toBeNull();
  });
});
