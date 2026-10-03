import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { testRenderHook } from '../tests/test-render';
import useTimeSeriesAxisFormatter from './useTimeSeriesAxisFormatter';

describe('Hook: useTimeSeriesAxisFormatter', () => {
  // The runner is forced to a negative offset: labelling in local time would render the
  // start of an UTC bucket as the previous period. See issue #12150.
  const initialTimeZone = process.env.TZ;
  beforeAll(() => {
    process.env.TZ = 'America/New_York';
  });
  afterAll(() => {
    // Assigning undefined would store the literal string 'undefined' and leave the
    // process without a resolvable default zone.
    if (initialTimeZone === undefined) {
      delete process.env.TZ;
    } else {
      process.env.TZ = initialTimeZone;
    }
  });

  it('should label a monthly bucket with its own UTC month', () => {
    const { hook } = testRenderHook(() => useTimeSeriesAxisFormatter('month'));
    expect(hook.result.current('2025-07-01T00:00:00.000Z')).toEqual('July 2025');
    expect(hook.result.current('2025-08-01T00:00:00.000Z')).toEqual('August 2025');
  });

  it('should label a quarterly bucket like a monthly one', () => {
    const { hook } = testRenderHook(() => useTimeSeriesAxisFormatter('quarter'));
    expect(hook.result.current('2025-07-01T00:00:00.000Z')).toEqual('July 2025');
  });

  it('should label a yearly bucket with its own UTC year', () => {
    const { hook } = testRenderHook(() => useTimeSeriesAxisFormatter('year'));
    expect(hook.result.current('2025-01-01T00:00:00.000Z')).toEqual('2025');
  });

  it('should label a daily bucket with its own UTC day', () => {
    const { hook } = testRenderHook(() => useTimeSeriesAxisFormatter('day'));
    expect(hook.result.current('2025-08-01T00:00:00.000Z')).toEqual('Aug 1, 2025');
  });

  it('should default to a daily label when no interval is given', () => {
    const { hook } = testRenderHook(() => useTimeSeriesAxisFormatter());
    expect(hook.result.current('2025-08-01T00:00:00.000Z')).toEqual('Aug 1, 2025');
  });
});
