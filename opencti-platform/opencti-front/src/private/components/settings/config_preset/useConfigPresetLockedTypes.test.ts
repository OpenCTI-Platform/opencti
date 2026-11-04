import { renderHook } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const enterpriseEdition = vi.hoisted(() => ({ enabled: false }));
vi.mock('../../../../utils/hooks/useEnterpriseEdition', () => ({ default: () => enterpriseEdition.enabled }));

import useConfigPresetLockedTypes from './useConfigPresetLockedTypes';

const platform = { key: 'platform', lockedByEnterpriseEdition: false };
const whitemarkLocked = { key: 'whitemark', lockedByEnterpriseEdition: true };
const whitemarkUsable = { key: 'whitemark', lockedByEnterpriseEdition: false };

describe('useConfigPresetLockedTypes', () => {
  beforeEach(() => {
    enterpriseEdition.enabled = false;
  });

  const run = (types: { key: string; lockedByEnterpriseEdition: boolean }[] | null) => {
    const reload = vi.fn();
    const onUsable = vi.fn();
    const hook = renderHook(({ current }) => useConfigPresetLockedTypes(current, reload, onUsable), { initialProps: { current: types } });
    return { reload, onUsable, ...hook };
  };

  it('announces nothing for the first types, locked or not', () => {
    const { onUsable } = run([platform, whitemarkLocked]);
    expect(onUsable).not.toHaveBeenCalled();
  });

  it('announces nothing for the types it receives once they are loaded', () => {
    const { onUsable, rerender } = run(null);
    rerender({ current: [platform, whitemarkUsable] });
    expect(onUsable).not.toHaveBeenCalled();
  });

  it('announces a type that was locked and is not, once', () => {
    const { onUsable, rerender } = run([platform, whitemarkLocked]);
    rerender({ current: [platform, whitemarkUsable] });
    expect(onUsable).toHaveBeenCalledTimes(1);
    expect(onUsable).toHaveBeenCalledWith([whitemarkUsable]);
    rerender({ current: [platform, whitemarkUsable] });
    expect(onUsable).toHaveBeenCalledTimes(1);
  });

  it('announces a type that was not there', () => {
    const { onUsable, rerender } = run([platform]);
    rerender({ current: [platform, whitemarkUsable] });
    expect(onUsable).toHaveBeenCalledWith([whitemarkUsable]);
  });

  it('does not announce a type that stays locked, nor one that was already usable', () => {
    const { onUsable, rerender } = run([platform, whitemarkLocked]);
    rerender({ current: [{ ...platform }, { ...whitemarkLocked }] });
    expect(onUsable).not.toHaveBeenCalled();
  });

  it('reads the types again when the license changes, not when it is first read', () => {
    const { reload, rerender } = run([platform, whitemarkLocked]);
    expect(reload).not.toHaveBeenCalled();
    enterpriseEdition.enabled = true;
    rerender({ current: [platform, whitemarkLocked] });
    expect(reload).toHaveBeenCalledTimes(1);
    rerender({ current: [platform, whitemarkLocked] });
    expect(reload).toHaveBeenCalledTimes(1);
  });
});
