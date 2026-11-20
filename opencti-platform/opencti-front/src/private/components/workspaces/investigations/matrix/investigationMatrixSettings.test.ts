import { describe, expect, it } from 'vitest';
import { act, renderHook } from '@testing-library/react';
import { DEFAULT_INVESTIGATION_MATRIX_SETTINGS, useInvestigationMatrixSettings } from './investigationMatrixSettings';

const PLATFORM = { value: 'platform-1', label: 'EDR', type: 'SecurityPlatform' };

describe('useInvestigationMatrixSettings', () => {
  it('starts from the defaults', () => {
    const { result } = renderHook(() => useInvestigationMatrixSettings('investigation-a'));
    expect(result.current[0]).toEqual(DEFAULT_INVESTIGATION_MATRIX_SETTINGS);
  });

  it('merges each change into the settings', () => {
    const { result } = renderHook(() => useInvestigationMatrixSettings('investigation-a'));
    act(() => result.current[1]({ heatmap: true }));
    act(() => result.current[1]({ killChain: 'mitre-attack', securityPlatforms: [PLATFORM] }));
    expect(result.current[0]).toEqual({ killChain: 'mitre-attack', onlyUsed: false, heatmap: true, securityPlatforms: [PLATFORM] });
  });

  it('gives another investigation the defaults, not the settings of the previous one', () => {
    const { result, rerender } = renderHook(({ id }) => useInvestigationMatrixSettings(id), { initialProps: { id: 'investigation-a' } });
    act(() => result.current[1]({ heatmap: true, onlyUsed: true, securityPlatforms: [PLATFORM] }));

    rerender({ id: 'investigation-b' });
    expect(result.current[0]).toEqual(DEFAULT_INVESTIGATION_MATRIX_SETTINGS);

    // A change on the new investigation starts from its defaults too.
    act(() => result.current[1]({ killChain: 'other-chain' }));
    expect(result.current[0]).toEqual({ ...DEFAULT_INVESTIGATION_MATRIX_SETTINGS, killChain: 'other-chain' });
  });
});
