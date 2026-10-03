import { describe, expect, it } from 'vitest';
import { huntWidgetVariables } from './WidgetHuntStatistics';

describe('huntWidgetVariables()', () => {
  const now = new Date('2026-10-03T12:00:00.000Z');

  it('should cover the last 30 days by day without a dashboard period', () => {
    expect(huntWidgetVariables(null, null, now)).toEqual({
      huntId: null,
      startDate: '2026-09-03T12:00:00.000Z',
      endDate: '2026-10-03T12:00:00.000Z',
      interval: 'day',
    });
  });

  it('should follow the dashboard period and widen the interval with it', () => {
    expect(huntWidgetVariables('2026-07-01T00:00:00.000Z', '2026-10-01T00:00:00.000Z', now)).toMatchObject({
      startDate: '2026-07-01T00:00:00.000Z',
      endDate: '2026-10-01T00:00:00.000Z',
      interval: 'week',
    });
    expect(huntWidgetVariables('2025-10-01T00:00:00.000Z', undefined, now)).toMatchObject({
      endDate: '2026-10-03T12:00:00.000Z',
      interval: 'month',
    });
  });
});
