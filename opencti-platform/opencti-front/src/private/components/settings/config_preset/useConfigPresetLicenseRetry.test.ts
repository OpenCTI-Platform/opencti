import { act, renderHook } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const enterpriseEdition = vi.hoisted(() => ({ enabled: true }));
vi.mock('../../../../utils/hooks/useEnterpriseEdition', () => ({ default: () => enterpriseEdition.enabled }));

import useConfigPresetLicenseRetry, { CONFIG_PRESET_LICENSE_MAX_RETRIES, CONFIG_PRESET_LICENSE_RETRY_DELAY_MS } from './useConfigPresetLicenseRetry';

const locked = () => [{ locked: true }];
const available = () => [{ locked: false }];

describe('useConfigPresetLicenseRetry', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    enterpriseEdition.enabled = true;
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  const run = (types: { locked: boolean }[]) => {
    const reload = vi.fn();
    const hook = renderHook(({ current }) => useConfigPresetLicenseRetry(current, reload), { initialProps: { current: types } });
    return { reload, ...hook };
  };
  const wait = (times = 1) => act(async () => {
    await vi.advanceTimersByTimeAsync(CONFIG_PRESET_LICENSE_RETRY_DELAY_MS * times);
  });

  it('reads again after a delay when the front end has the license and the backend still locks a type', async () => {
    const { reload } = run(locked());
    expect(reload).not.toHaveBeenCalled();
    await wait();
    expect(reload).toHaveBeenCalledTimes(1);
  });

  it('keeps reading again while the backend answers locked, and gives up after a few times', async () => {
    const { reload, rerender } = run(locked());
    for (let i = 0; i < CONFIG_PRESET_LICENSE_MAX_RETRIES + 2; i += 1) {
      await wait();
      rerender({ current: locked() });
    }
    expect(reload).toHaveBeenCalledTimes(CONFIG_PRESET_LICENSE_MAX_RETRIES);
  });

  it('stops as soon as the backend has taken the license into account, and starts again for the next one', async () => {
    const { reload, rerender } = run(locked());
    await wait();
    rerender({ current: available() });
    await wait(2);
    expect(reload).toHaveBeenCalledTimes(1);
    rerender({ current: locked() });
    await wait();
    expect(reload).toHaveBeenCalledTimes(2);
  });

  it('does nothing on a platform that has no license, whatever the backend says', async () => {
    enterpriseEdition.enabled = false;
    const { reload } = run(locked());
    await wait(3);
    expect(reload).not.toHaveBeenCalled();
  });

  it('does nothing while the types are not loaded', async () => {
    const reload = vi.fn();
    renderHook(() => useConfigPresetLicenseRetry(undefined, reload));
    await wait(3);
    expect(reload).not.toHaveBeenCalled();
  });
});
