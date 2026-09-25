import { afterEach, describe, expect, it } from 'vitest';
import moment from 'moment';
import { buildBucketDateFilter } from './widgetDrilldownFilters';

const NO_RANGE = { startDate: null, endDate: null };

/**
 * Reproduces what the API actually returns for the bucket starting on the given
 * calendar date. `fillTimeSeries` builds period starts in the browser's offset
 * then converts to UTC, so the instant depends on the timezone of the process:
 * a CET browser receives `2024-01-31T23:00:00.000Z` for February 2024.
 *
 * Fixtures must therefore be derived, never hardcoded — a hardcoded UTC
 * midnight describes a bucket no browser east or west of UTC could ever emit,
 * and would make the timezone sweep below pass for the wrong reason.
 */
const apiBucketDate = (periodStart: string) => moment(periodStart, 'YYYY-MM-DD').utc().toISOString();

describe('buildBucketDateFilter', () => {
  it('builds an inclusive lower bound and an exclusive upper bound', () => {
    const filters = buildBucketDateFilter(apiBucketDate('2024-03-01'), 'month', NO_RANGE, 'created_at');
    expect(filters).toEqual([
      { key: 'created_at', values: ['2024-03-01T00:00:00.000Z'], operator: 'gte', mode: 'or' },
      { key: 'created_at', values: ['2024-04-01T00:00:00.000Z'], operator: 'lt', mode: 'or' },
    ]);
  });

  it('handles each supported interval', () => {
    expect(buildBucketDateFilter(apiBucketDate('2024-03-04'), 'day', NO_RANGE, 'created_at')?.[1].values[0])
      .toEqual('2024-03-05T00:00:00.000Z');
    // 2024-03-04 is a Monday, matching Elasticsearch's week start.
    expect(buildBucketDateFilter(apiBucketDate('2024-03-04'), 'week', NO_RANGE, 'created_at')?.[1].values[0])
      .toEqual('2024-03-11T00:00:00.000Z');
    expect(buildBucketDateFilter(apiBucketDate('2024-04-01'), 'quarter', NO_RANGE, 'created_at')?.[1].values[0])
      .toEqual('2024-07-01T00:00:00.000Z');
    expect(buildBucketDateFilter(apiBucketDate('2024-01-01'), 'year', NO_RANGE, 'created_at')?.[1].values[0])
      .toEqual('2025-01-01T00:00:00.000Z');
  });

  it('clamps the first bucket to the widget start date', () => {
    const range = { startDate: '2024-01-15T00:00:00.000Z', endDate: null };
    const filters = buildBucketDateFilter(apiBucketDate('2024-01-01'), 'month', range, 'created_at');
    expect(filters?.[0]).toEqual({
      key: 'created_at', values: ['2024-01-15T00:00:00.000Z'], operator: 'gte', mode: 'or',
    });
    expect(filters?.[1].values[0]).toEqual('2024-02-01T00:00:00.000Z');
  });

  it('clamps the last bucket to the widget end date and switches to lte', () => {
    const range = { startDate: null, endDate: '2024-03-20T00:00:00.000Z' };
    const filters = buildBucketDateFilter(apiBucketDate('2024-03-01'), 'month', range, 'created_at');
    expect(filters?.[1]).toEqual({
      key: 'created_at', values: ['2024-03-20T00:00:00.000Z'], operator: 'lte', mode: 'or',
    });
  });

  it('does not clamp a middle bucket', () => {
    const range = { startDate: '2024-01-15T00:00:00.000Z', endDate: '2024-05-20T00:00:00.000Z' };
    const filters = buildBucketDateFilter(apiBucketDate('2024-03-01'), 'month', range, 'created_at');
    expect(filters?.[0].operator).toEqual('gte');
    expect(filters?.[1].operator).toEqual('lt');
  });

  it('uses the configured date attribute', () => {
    const filters = buildBucketDateFilter(apiBucketDate('2024-03-01'), 'month', NO_RANGE, 'published');
    expect(filters?.every((f) => f.key === 'published')).toBe(true);
  });

  it('returns null for an unsupported interval', () => {
    expect(buildBucketDateFilter(apiBucketDate('2024-03-01'), 'fortnight', NO_RANGE, 'created_at')).toBeNull();
  });

  it('returns null for an invalid date', () => {
    expect(buildBucketDateFilter('not-a-date', 'month', NO_RANGE, 'created_at')).toBeNull();
  });
});

describe('buildBucketDateFilter timezone recovery', () => {
  const originalTz = process.env.TZ;

  afterEach(() => {
    if (originalTz === undefined) delete process.env.TZ;
    else process.env.TZ = originalTz;
  });

  /**
   * The February 2024 bucket as emitted by a browser in each zone. Elasticsearch
   * counted the true UTC month in every case, so all three must resolve to the
   * same boundaries whatever the timezone of the process running the test.
   */
  it.each([
    ['Europe/Paris', '2024-01-31T23:00:00.000Z'],
    ['Pacific/Kiritimati', '2024-01-31T10:00:00.000Z'],
    ['Pacific/Midway', '2024-02-01T11:00:00.000Z'],
    ['UTC', '2024-02-01T00:00:00.000Z'],
  ])('recovers the February 2024 boundaries from a date skewed by %s', (timezone, bucketDate) => {
    process.env.TZ = timezone;
    const filters = buildBucketDateFilter(bucketDate, 'month', NO_RANGE, 'created_at');
    expect(filters?.[0].values[0]).toEqual('2024-02-01T00:00:00.000Z');
    expect(filters?.[1].values[0]).toEqual('2024-03-01T00:00:00.000Z');
  });
});
