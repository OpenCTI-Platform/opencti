/**
 * Unit tests of the public time series breakdowns: every breakdown setting is read from the stored widget, the visitor
 * only gives the period. Only the breakdowns of entities and relationships widgets are public: audits widgets can
 * carry a breakdown as well, but the logs have no public API.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  buildPublicBreakdownArgs,
  canWidgetBreakDown,
  clampPublicBreakdownStartDate,
  fitPublicBreakdownPeriod,
  getBreakdownEntityTypes,
  PUBLIC_BREAKDOWN_MAX_POINTS,
  withPublicBreakdownRefusals,
} from '../../../../src/modules/publicDashboard/publicDashboard-breakdown';
import { DatabaseError, FunctionalError, UnsupportedError } from '../../../../src/config/errors';
import { countTimeSeriesIntervals } from '../../../../src/database/utils';

const startDate = '2026-01-01T00:00:00.000Z';
const endDate = '2026-02-01T00:00:00.000Z';

const targets = { mode: 'and', filters: [{ key: ['relationship_type'], values: ['targets'], operator: 'eq', mode: 'or' }], filterGroups: [] };
const malwares = { mode: 'and', filters: [{ key: ['entity_type'], values: ['Malware'], operator: 'eq', mode: 'or' }], filterGroups: [] };
const sectors = { mode: 'and', filters: [{ key: ['entity_type'], values: ['Sector'], operator: 'eq', mode: 'or' }], filterGroups: [] };
const breakdownParameters = { interval: 'week', breakdownBy: 'toTypes', breakdownLimit: 20, breakdownOrder: 'asc', breakdownOther: true };
// The relationships the relationships widgets display, as the front restricts them (RELATIONSHIP_WIDGETS_TYPES)
const relationshipWidgetsTypes = ['stix-core-relationship', 'stix-sighting-relationship', 'object', 'object-label'];
const widgetRelationships = (storedFilters?: unknown) => ({
  mode: 'and',
  filters: [{ key: ['entity_type'], values: relationshipWidgetsTypes, operator: 'eq', mode: 'or' }],
  filterGroups: storedFilters ? [storedFilters] : [],
});

const storedWidget = (perspective: string | null, dataSelection: unknown[], parameters: unknown, type = 'line') => {
  return { type, perspective, dataSelection, parameters } as any;
};
const request = (overrides: Record<string, unknown> = {}) => ({ widgetId: 'widget-1', startDate, endDate, ...overrides } as any);
const refusal = (message: string, code = 'FUNCTIONAL_ERROR') => expect.objectContaining({ message, extensions: expect.objectContaining({ code }) });
const drafts = { mode: 'and', filters: [{ key: ['entity_type'], values: ['DraftWorkspace'], operator: 'eq', mode: 'or' }], filterGroups: [] };

describe('buildPublicBreakdownArgs of relationships', () => {
  const relationshipsArgs = (widget: unknown, overrides: Record<string, unknown> = {}) => {
    return buildPublicBreakdownArgs(request(overrides), widget as any, 'relationships');
  };

  it('should break the stored dataset down with the stored settings', () => {
    const widget = storedWidget('relationships', [{ date_attribute: 'start_time', filters: targets, dynamicFrom: malwares, dynamicTo: sectors, isTo: false }], breakdownParameters);
    const args = relationshipsArgs(widget);

    expect(args).toEqual({
      field: 'toTypes',
      dateAttribute: 'start_time',
      startDate,
      endDate,
      interval: 'week',
      limit: 20,
      orderMode: 'asc',
      includeOther: true,
      // the stored filters, restricted to the relationships the widget displays
      filters: widgetRelationships(targets),
      dynamicFrom: malwares,
      dynamicTo: sectors,
      // the field is checked against the relationship types the filters restrict to
      relationship_type: ['targets'],
    });
    // Like the relationships time series, the displayed side of the widget plays no part
    expect(args).not.toHaveProperty('isTo');
  });

  it('should leave the settings the widget does not set to the API, and break all the relationships down without type filter', () => {
    const widget = storedWidget('relationships', [{ date_attribute: 'created_at' }], { breakdownBy: 'relationship_type' });

    // Without limit, order nor Other: the API defaults them. The interval has no default there.
    expect(relationshipsArgs(widget, { endDate: null })).toEqual({
      field: 'relationship_type',
      dateAttribute: 'created_at',
      startDate,
      endDate: null,
      interval: 'day',
      filters: widgetRelationships(),
      relationship_type: [],
    });
  });

  it('should only break the relationships the widgets display down, without relationship type filter', () => {
    // Without relationship type, every relationship would be broken down: the markings, the authors or the external
    // references of the elements too, which can fill the top values
    const notRevoked = { mode: 'and', filters: [{ key: ['revoked'], values: ['false'], operator: 'eq', mode: 'or' }], filterGroups: [] };
    for (const filters of [undefined, notRevoked]) {
      const widget = storedWidget('relationships', [{ date_attribute: 'created_at', filters, dynamicFrom: malwares }], { breakdownBy: 'relationship_type' });

      expect(relationshipsArgs(widget)).toMatchObject({
        filters: widgetRelationships(filters),
        dynamicFrom: malwares,
        relationship_type: [],
      });
    }
  });

  it('should refuse a widget without breakdown, or a request without start date', () => {
    expect(() => relationshipsArgs(storedWidget('relationships', [{ date_attribute: 'created_at', filters: targets }], { interval: 'day' })))
      .toThrow(refusal('This widget has no breakdown', 'UNSUPPORTED_ERROR'));
    const widget = storedWidget('relationships', [{ date_attribute: 'created_at', filters: targets }], breakdownParameters);
    expect(() => relationshipsArgs(widget, { startDate: null })).toThrow(refusal('A start date is required for a time series breakdown'));
  });

  it('should refuse the widgets broken down on another perspective, whose public breakdown is another query', () => {
    for (const perspective of ['entities', 'audits']) {
      const widget = storedWidget(perspective, [{ date_attribute: 'created_at', filters: malwares }], breakdownParameters);
      expect(() => relationshipsArgs(widget)).toThrow(refusal('This widget is broken down on another perspective'));
    }
  });

  it('should refuse the widgets that cannot be broken down, still carrying a breakdown', () => {
    // Edited without the breakdown feature, or imported: the dashboards draw their regular chart, the public manifest
    // serves them without breakdown
    const relationships = { date_attribute: 'created_at', perspective: 'relationships', filters: targets };
    const stale = [
      { type: 'donut', dataSelection: [relationships] },
      { type: 'line', dataSelection: [relationships, relationships] },
      { type: 'line', dataSelection: [] },
      // a relationships widget can hold entities datasets, which cannot be broken down as relationships
      { type: 'vertical-bar', dataSelection: [{ ...relationships, perspective: 'entities', filters: malwares }] },
      { type: 'line', dataSelection: [{ ...relationships, filters: drafts }] },
    ];
    for (const { type, dataSelection } of stale) {
      const widget = storedWidget('relationships', dataSelection, breakdownParameters, type);
      expect(() => relationshipsArgs(widget)).toThrow(refusal('This widget cannot be broken down'));
    }
    // A widget without perspective is no time series of elements
    expect(() => relationshipsArgs(storedWidget(null, [relationships], breakdownParameters))).toThrow(refusal('This widget cannot be broken down'));
  });

  it('should count a long period in coarser intervals, keeping the whole period', () => {
    // 20 series and Other, hourly: the 745 hours of January would be 15,645 points, its 32 days are 672
    const widget = storedWidget('relationships', [{ date_attribute: 'created_at', filters: targets }], { ...breakdownParameters, interval: 'hour' });
    const args = relationshipsArgs(widget);
    expect(args).toMatchObject({ interval: 'day', startDate, endDate });
    expect(countTimeSeriesIntervals(args.startDate, new Date(endDate), args.interval) * 21).toBeLessThanOrEqual(PUBLIC_BREAKDOWN_MAX_POINTS);
    // Without limit, the 10 series of the API: 7,450 hourly points, 320 daily ones
    const defaultLimit = relationshipsArgs(storedWidget('relationships', [{ date_attribute: 'created_at' }], { breakdownBy: 'toTypes', interval: 'hour' }));
    expect(defaultLimit).toMatchObject({ interval: 'day', startDate });
    // A short period keeps the interval of the widget
    const shortPeriod = relationshipsArgs(storedWidget('relationships', [{ date_attribute: 'created_at' }], breakdownParameters));
    expect(shortPeriod).toMatchObject({ interval: breakdownParameters.interval, startDate });
  });

  it('should break down every time series of a single relationships dataset', () => {
    for (const type of ['vertical-bar', 'line', 'area', 'heatmap']) {
      const widget = storedWidget('relationships', [{ date_attribute: 'created_at', perspective: 'relationships', filters: targets }], breakdownParameters, type);
      expect(relationshipsArgs(widget)).toMatchObject({ field: 'toTypes', relationship_type: ['targets'] });
    }
  });
});

describe('buildPublicBreakdownArgs of entities', () => {
  const entitiesArgs = (widget: unknown) => buildPublicBreakdownArgs(request(), widget as any, 'entities');

  it('should break the stored entities dataset down with the stored settings', () => {
    const reports = { mode: 'and', filters: [{ key: ['entity_type'], values: ['Report'], operator: 'eq', mode: 'or' }], filterGroups: [] };
    const widget = storedWidget('entities', [{ date_attribute: 'published', filters: reports }], { interval: 'month', breakdownBy: 'objectLabel', breakdownLimit: 5, breakdownOrder: 'desc' });

    expect(entitiesArgs(widget)).toEqual({
      field: 'objectLabel',
      dateAttribute: 'published',
      startDate,
      endDate,
      interval: 'month',
      limit: 5,
      orderMode: 'desc',
      filters: reports,
      // the field is checked against the types the filters restrict to
      types: ['Report'],
    });
  });

  it('should leave the types to the API without type filter, which breaks every entity down', () => {
    const widget = storedWidget('entities', [{ date_attribute: 'created_at' }], { breakdownBy: 'entity_type' });
    expect(entitiesArgs(widget)).toMatchObject({ filters: undefined, types: [] });
  });

  it('should refuse an audits widget carrying a breakdown: the logs have no public breakdown', () => {
    const widget = storedWidget('audits', [{ date_attribute: 'timestamp', filters: null }], { interval: 'day', breakdownBy: 'event_scope', breakdownLimit: 5 });
    expect(() => entitiesArgs(widget)).toThrow(refusal('This widget is broken down on another perspective'));
    // Counting the distinct values of an attribute, its line cannot be broken down at all
    const distinctValues = storedWidget('audits', [{ date_attribute: 'timestamp', unique: true }], { breakdownBy: 'event_scope' });
    expect(() => entitiesArgs(distinctValues)).toThrow(refusal('This widget cannot be broken down'));
  });

  it('should refuse a relationships widget, broken down through the query of the relationships', () => {
    const widget = storedWidget('relationships', [{ date_attribute: 'created_at', filters: targets }], breakdownParameters);
    expect(() => entitiesArgs(widget)).toThrow(refusal('This widget is broken down on another perspective'));
  });

  it('should refuse the entities widgets that cannot be broken down, still carrying a breakdown', () => {
    const entities = { date_attribute: 'published', perspective: 'entities', filters: malwares };
    const stale = [
      { perspective: 'entities', type: 'number', dataSelection: [entities] },
      { perspective: 'entities', type: 'area', dataSelection: [entities, entities] },
      { perspective: 'entities', type: 'area', dataSelection: [{ ...entities, perspective: 'relationships' }] },
      // drafts cannot be broken down, as the front refuses them: a dataset of draft workspaces only
      { perspective: 'entities', type: 'area', dataSelection: [{ ...entities, filters: drafts }] },
      { perspective: null, type: 'line', dataSelection: [entities] },
    ];
    for (const { perspective, type, dataSelection } of stale) {
      const widget = storedWidget(perspective, dataSelection, { interval: 'day', breakdownBy: 'objectLabel' }, type);
      expect(() => entitiesArgs(widget)).toThrow(refusal('This widget cannot be broken down'));
    }
  });
});

describe('fitPublicBreakdownPeriod', () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it('should keep the interval and the period that fit', () => {
    // 32 days of 11 series
    expect(fitPublicBreakdownPeriod(startDate, endDate, 'day', 11)).toEqual({ interval: 'day', startDate });
    // 51 series of the 98 weeks that fit exactly: the budget is reached, not exceeded
    const start = new Date(Date.UTC(2024, 2, 18)).toISOString();
    expect(fitPublicBreakdownPeriod(start, endDate, 'week', 51)).toEqual({ interval: 'week', startDate: start });
  });

  it('should take the first coarser interval that fits, the steps of the dashboards', () => {
    // Two years of days: 731 days, 105 weeks, 24 months
    const twoYears = '2024-02-01T00:00:00.000Z';
    // 10 series and Other: 454 dates at most, the weeks fit
    expect(fitPublicBreakdownPeriod(twoYears, endDate, 'day', 11)).toEqual({ interval: 'week', startDate: twoYears });
    // 50 series and Other: 98 dates at most, the months fit
    expect(fitPublicBreakdownPeriod(twoYears, endDate, 'day', 51)).toEqual({ interval: 'month', startDate: twoYears });
    // 5 series: 1,000 dates at most, the days fit
    expect(fitPublicBreakdownPeriod(twoYears, endDate, 'day', 5)).toEqual({ interval: 'day', startDate: twoYears });
    // Hours go to days first: 745 hours of 11 series do not fit, 32 days do
    expect(fitPublicBreakdownPeriod(startDate, endDate, 'hour', 11)).toEqual({ interval: 'day', startDate });
    // 51 series over 30 years: 30 years, not 120 quarters
    expect(fitPublicBreakdownPeriod('1996-01-01T00:00:00.000Z', endDate, 'month', 51)).toEqual({ interval: 'year', startDate: '1996-01-01T00:00:00.000Z' });
  });

  it('should move the start date forward only when even years do not fit', () => {
    // 51 series: 98 years at most, the 127 years since 1900 are cut to the 98 most recent ones
    const fitted = fitPublicBreakdownPeriod('1900-01-01T00:00:00.000Z', endDate, 'day', 51);
    expect(fitted.interval).toEqual('year');
    expect(new Date(fitted.startDate).toISOString()).toEqual('1929-01-01T00:00:00.000Z');
    expect(countTimeSeriesIntervals(fitted.startDate, new Date(endDate), 'year')).toEqual(98);
  });

  it('should count the period up to now without end date', () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(new Date('2026-02-01T00:30:00.000Z'));
    expect(fitPublicBreakdownPeriod(startDate, null, 'hour', 11)).toEqual({ interval: 'day', startDate });
  });

  it('should leave the limits the API refuses, and the unsupported intervals, to the API', () => {
    expect(fitPublicBreakdownPeriod('2020-01-01T00:00:00.000Z', endDate, 'hour', 0)).toEqual({ interval: 'hour', startDate: '2020-01-01T00:00:00.000Z' });
    expect(fitPublicBreakdownPeriod('2020-01-01T00:00:00.000Z', endDate, 'hour', 2.5)).toEqual({ interval: 'hour', startDate: '2020-01-01T00:00:00.000Z' });
    expect(() => fitPublicBreakdownPeriod(startDate, endDate, 'minute', 11)).toThrow('Unsupported interval');
  });
});

describe('clampPublicBreakdownStartDate', () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it('should keep the most recent dates of a long hourly period that fit the points of the public breakdowns', () => {
    // 11 series (10 and Other) of 454 hours: 4,994 points, one more hour would be 5,005. The 745 hours of January would be 8,195.
    const clamped = clampPublicBreakdownStartDate(startDate, endDate, 'hour', 11);
    expect(new Date(clamped).toISOString()).toEqual('2026-01-13T03:00:00.000Z');
    expect(countTimeSeriesIntervals(clamped, new Date(endDate), 'hour')).toEqual(454);
    expect(454 * 11).toBeLessThanOrEqual(PUBLIC_BREAKDOWN_MAX_POINTS);
    expect(455 * 11).toBeGreaterThan(PUBLIC_BREAKDOWN_MAX_POINTS);
  });

  it('should leave a period that fits untouched', () => {
    // 32 days of 11 series
    expect(clampPublicBreakdownStartDate(startDate, endDate, 'day', 11)).toBe(startDate);
    // 51 series of the 98 weeks that fit exactly: the budget is reached, not exceeded
    const start = new Date(Date.UTC(2024, 2, 18)).toISOString();
    expect(countTimeSeriesIntervals(new Date(start), new Date(endDate), 'week')).toEqual(98);
    expect(clampPublicBreakdownStartDate(start, endDate, 'week', 51)).toBe(start);
  });

  it('should start on the first day of an interval, as the buckets of the breakdown', () => {
    const weekly = clampPublicBreakdownStartDate('2020-01-01T00:00:00.000Z', endDate, 'week', 51);
    // a monday, 97 weeks before the one of the end date (monday 2026-01-26)
    expect(new Date(weekly).toISOString()).toEqual('2024-03-18T00:00:00.000Z');
    expect(countTimeSeriesIntervals(weekly, new Date(endDate), 'week')).toEqual(98);
    // Daily, 50 series: 100 days
    const daily = clampPublicBreakdownStartDate('2020-01-01T00:00:00.000Z', '2026-02-01T12:30:00.000Z', 'day', 50);
    expect(new Date(daily).toISOString()).toEqual('2025-10-25T00:00:00.000Z');
    expect(countTimeSeriesIntervals(daily, new Date('2026-02-01T12:30:00.000Z'), 'day')).toEqual(100);
  });

  it('should count the period up to now without end date', () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(new Date('2026-02-01T00:30:00.000Z'));
    // The hour of now and the 453 before it
    expect(new Date(clampPublicBreakdownStartDate(startDate, null, 'hour', 11)).toISOString()).toEqual('2026-01-13T03:00:00.000Z');
  });

  it('should leave the limits the API refuses, and the unsupported intervals, to the API', () => {
    expect(clampPublicBreakdownStartDate('2020-01-01T00:00:00.000Z', endDate, 'hour', 0)).toEqual('2020-01-01T00:00:00.000Z');
    expect(clampPublicBreakdownStartDate('2020-01-01T00:00:00.000Z', endDate, 'hour', 2.5)).toEqual('2020-01-01T00:00:00.000Z');
    expect(() => clampPublicBreakdownStartDate(startDate, endDate, 'minute', 11)).toThrow('Unsupported interval');
  });
});

describe('canWidgetBreakDown', () => {
  const widget = (overrides: Record<string, unknown> = {}) => ({ type: 'line', perspective: 'entities', dataSelection: [{ filters: malwares }], ...overrides } as any);

  it('should break down a time series of a single dataset of the elements of the widget, outside the drafts', () => {
    for (const type of ['vertical-bar', 'line', 'area', 'heatmap']) {
      expect(canWidgetBreakDown(widget({ type }))).toEqual(true);
    }
    expect(canWidgetBreakDown(widget({ perspective: 'relationships', dataSelection: [{ perspective: 'relationships', filters: targets }] }))).toEqual(true);
    expect(canWidgetBreakDown(widget({ perspective: 'audits', dataSelection: [{}] }))).toEqual(true);
    // Draft workspaces among other types are not a dataset of drafts only, as for the front
    const withDrafts = { ...drafts, filters: [{ ...drafts.filters[0], values: ['DraftWorkspace', 'Malware'] }] };
    expect(canWidgetBreakDown(widget({ dataSelection: [{ filters: withDrafts }] }))).toEqual(true);
  });

  it('should not break down the other widgets', () => {
    expect(canWidgetBreakDown(widget({ type: 'donut' }))).toEqual(false);
    expect(canWidgetBreakDown(widget({ perspective: null }))).toEqual(false);
    expect(canWidgetBreakDown(widget({ dataSelection: [] }))).toEqual(false);
    expect(canWidgetBreakDown(widget({ dataSelection: [{ filters: malwares }, { filters: sectors }] }))).toEqual(false);
    expect(canWidgetBreakDown(widget({ perspective: 'relationships', dataSelection: [{ perspective: 'entities', filters: malwares }] }))).toEqual(false);
    // The key of a stored filter can be a string as well
    expect(canWidgetBreakDown(widget({ dataSelection: [{ filters: drafts }] }))).toEqual(false);
    expect(canWidgetBreakDown(widget({ dataSelection: [{ filters: { ...drafts, filters: [{ ...drafts.filters[0], key: 'entity_type' }] } }] }))).toEqual(false);
    // The audits lines and areas counting distinct values, not their bars, which count every event
    expect(canWidgetBreakDown(widget({ perspective: 'audits', type: 'area', dataSelection: [{ unique: true }] }))).toEqual(false);
    expect(canWidgetBreakDown(widget({ perspective: 'audits', type: 'vertical-bar', dataSelection: [{ unique: true }] }))).toEqual(true);
  });
});

describe('getBreakdownEntityTypes', () => {
  const typeFilter = (values: string[], overrides: Record<string, unknown> = {}) => ({ key: ['entity_type'], values, operator: 'eq', mode: 'or', ...overrides });
  const notRevoked = { key: ['revoked'], values: ['false'], operator: 'eq', mode: 'or' };
  const group = (filters: unknown[], overrides: Record<string, unknown> = {}) => ({ mode: 'and', filters, filterGroups: [], ...overrides }) as any;

  it('should read the types of a top level type filter, whatever the form of its key', () => {
    expect(getBreakdownEntityTypes(group([typeFilter(['Report', 'Malware']), notRevoked]))).toEqual(['Report', 'Malware']);
    expect(getBreakdownEntityTypes(group([typeFilter(['Report'], { key: 'entity_type' })]))).toEqual(['Report']);
    // The relationship type of the relationships
    const relationshipTargets = typeFilter(['targets'], { key: ['relationship_type'] });
    expect(getBreakdownEntityTypes(group([relationshipTargets]), 'relationship_type')).toEqual(['targets']);
    expect(getBreakdownEntityTypes(group([relationshipTargets]))).toEqual([]);
  });

  it('should not restrict the types of a group in "or" with several entries', () => {
    expect(getBreakdownEntityTypes(group([typeFilter(['Report']), notRevoked], { mode: 'or' }))).toEqual([]);
    expect(getBreakdownEntityTypes(group([typeFilter(['Report'])], { mode: 'or', filterGroups: [group([notRevoked])] }))).toEqual([]);
    // A single entry restricts the types whatever the mode of its group
    expect(getBreakdownEntityTypes(group([typeFilter(['Report'])], { mode: 'or' }))).toEqual(['Report']);
  });

  it('should not restrict the types of a type filter excluding them', () => {
    expect(getBreakdownEntityTypes(group([typeFilter(['Report'], { operator: 'not_eq' })]))).toEqual([]);
    // Without operator, a filter is an equality
    expect(getBreakdownEntityTypes(group([typeFilter(['Report'], { operator: undefined })]))).toEqual(['Report']);
  });

  it('should only read several types in "and" as no restriction, a single one restricts the type', () => {
    // Elements of every type at once
    expect(getBreakdownEntityTypes(group([typeFilter(['Report', 'Malware'], { mode: 'and' })]))).toEqual([]);
    expect(getBreakdownEntityTypes(group([typeFilter(['Report'], { mode: 'and' })]))).toEqual(['Report']);
  });

  it('should read the stored filters missing a key', () => {
    expect(getBreakdownEntityTypes({ mode: 'and', filters: [typeFilter(['Report'])] } as any)).toEqual(['Report']);
    expect(getBreakdownEntityTypes({ mode: 'or', filters: [typeFilter(['Report'])] } as any)).toEqual(['Report']);
    expect(getBreakdownEntityTypes({ mode: 'and', filterGroups: [] } as any)).toEqual([]);
    expect(getBreakdownEntityTypes({ mode: 'and', filters: [{ key: ['entity_type'], operator: 'eq', mode: 'or' }] } as any)).toEqual([]);
    expect(getBreakdownEntityTypes(null)).toEqual([]);
  });
});

describe('withPublicBreakdownRefusals', () => {
  const refusedWith = async (error: unknown) => {
    try {
      await withPublicBreakdownRefusals(() => Promise.reject(error));
    } catch (thrown) {
      return thrown as any;
    }
    throw new Error('The breakdown was not refused');
  };

  it('should give the breakdown when it is not refused', async () => {
    const breakdown = { truncated: false, dates: [], series: [] };
    await expect(withPublicBreakdownRefusals(() => Promise.resolve(breakdown))).resolves.toBe(breakdown);
  });

  it('should keep the message and the reason of a refusal, never the types of the stored filters', async () => {
    // As the breakdown API refuses a field or a date attribute (resolveBreakdownField, checkBreakdownDateAttribute)
    const refusals = [
      { reason: 'unsupported_field', error: FunctionalError('Time series breakdown does not support this field for these entity types', { reason: 'unsupported_field', field: 'report_types', types: ['Report'] }) },
      { reason: 'unsupported_date_attribute', error: FunctionalError('Time series breakdown does not support this date attribute for these types', { reason: 'unsupported_date_attribute', dateAttribute: 'name', types: ['Report'] }) },
    ];
    for (const { reason, error } of refusals) {
      const thrown = await refusedWith(error);
      expect(thrown.message).toEqual(error.message);
      expect(thrown.extensions).toEqual({ code: 'FUNCTIONAL_ERROR', data: { http_status: 400, genre: 'BUSINESS', reason } });
    }
  });

  it('should keep no data of a refusal without reason', async () => {
    const thrown = await refusedWith(FunctionalError('Unsupported interval, please choose between year, quarter, month, week, day or hour', { interval: 'minute' }));
    expect(thrown.message).toEqual('Unsupported interval, please choose between year, quarter, month, week, day or hour');
    expect(thrown.extensions.data).not.toHaveProperty('interval');
    expect(thrown.extensions.data.reason).toBeUndefined();
  });

  it('should leave the other errors as they are', async () => {
    const others = [UnsupportedError('This widget has no breakdown', { widgetId: 'widget-1' }), DatabaseError('Engine execution fail'), new Error('Unexpected')];
    for (const other of others) {
      expect(await refusedWith(other)).toBe(other);
    }
    // Refused before any promise, like a widget without breakdown
    const unsupported = UnsupportedError('This widget has no breakdown', { widgetId: 'widget-1' });
    await expect(withPublicBreakdownRefusals(() => {
      throw unsupported;
    })).rejects.toBe(unsupported);
  });
});
