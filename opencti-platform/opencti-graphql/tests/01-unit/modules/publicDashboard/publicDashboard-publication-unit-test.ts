import { describe, expect, it } from 'vitest';
import { applyPublicationTimeRange, buildPublicationVariableValues, toPublicationTimeZone } from '../../../../src/modules/publicDashboard/publicDashboard-publication';

const TEXT = '11111111-1111-4111-8111-111111111111';
const NUMERIC = '22222222-2222-4222-8222-222222222222';
const SELECTION = '33333333-3333-4333-8333-333333333333';
const UNUSED = '44444444-4444-4444-8444-444444444444';
const UNKNOWN = '55555555-5555-4555-8555-555555555555';
const VARIABLES = [
  { id: TEXT, name: 'Text', type: 'text', restriction: { mode: 'none' }, defaultValue: 'x' },
  { id: NUMERIC, name: 'Numeric', type: 'numeric', restriction: { mode: 'none' }, defaultValue: '1' },
  { id: SELECTION, name: 'Selection', type: 'text', restriction: { mode: 'selection', values: ['a', 'b'] }, defaultValue: 'a' },
  // Used by no widget: a value is still accepted, it just has no effect on the published widgets
  { id: UNUSED, name: 'Unused', type: 'text', restriction: { mode: 'none' }, defaultValue: 'u' },
];

describe('buildPublicationVariableValues', () => {
  it('should use the provided values over the defaults', () => {
    const values = buildPublicationVariableValues(VARIABLES, [{ variable_id: TEXT, value: 'y' }]);
    expect(values.get(TEXT)).toEqual('y');
    expect(values.get(NUMERIC)).toEqual('1');
  });

  it('should keep the default when no value or an empty value is provided', () => {
    expect(buildPublicationVariableValues(VARIABLES, null).get(TEXT)).toEqual('x');
    expect(buildPublicationVariableValues(VARIABLES, [{ variable_id: TEXT, value: '  ' }]).get(TEXT)).toEqual('x');
  });

  it('should refuse an unknown variable', () => {
    expect(() => buildPublicationVariableValues(VARIABLES, [{ variable_id: UNKNOWN, value: 'y' }])).toThrow('Unknown dashboard variable');
  });

  it('should refuse a value invalid for its type', () => {
    expect(() => buildPublicationVariableValues(VARIABLES, [{ variable_id: NUMERIC, value: 'abc' }])).toThrow('Invalid dashboard variable value');
  });

  it('should refuse a value referencing another variable', () => {
    expect(() => buildPublicationVariableValues(VARIABLES, [{ variable_id: TEXT, value: `$var:${NUMERIC}` }])).toThrow('Invalid dashboard variable value');
  });

  it('should refuse the same variable twice', () => {
    const provided = [{ variable_id: TEXT, value: 'y' }, { variable_id: TEXT, value: 'z' }];
    expect(() => buildPublicationVariableValues(VARIABLES, provided)).toThrow('Duplicated dashboard variable value');
  });

  it('should accept a value outside the selection of the variable', () => {
    expect(buildPublicationVariableValues(VARIABLES, [{ variable_id: SELECTION, value: 'c' }]).get(SELECTION)).toEqual('c');
  });

  it('should accept a value for a variable used by no widget', () => {
    expect(buildPublicationVariableValues(VARIABLES, [{ variable_id: UNUSED, value: 'v' }]).get(UNUSED)).toEqual('v');
  });

  it('should refuse any value when the manifest holds no variable', () => {
    expect(() => buildPublicationVariableValues(undefined, [{ variable_id: TEXT, value: 'y' }])).toThrow('Unknown dashboard variable');
  });
});

describe('applyPublicationTimeRange', () => {
  const config = { relativeDate: 'months-1', startDate: null, endDate: null, refresh_interval: 5, allowViewersToEditTimeFilters: true };

  it('should keep the config without range', () => {
    expect(applyPublicationTimeRange(config, null)).toEqual(config);
    expect(applyPublicationTimeRange(undefined, undefined)).toEqual({});
  });

  it('should clear the absolute dates with a relative date', () => {
    expect(applyPublicationTimeRange({}, { relative_date: 'days-7', start_date: '2026-01-01', end_date: '2026-02-01' }))
      .toEqual({ relativeDate: 'days-7', startDate: null, endDate: null });
  });

  it('should write the absolute dates without relative date', () => {
    expect(applyPublicationTimeRange({}, { start_date: '2026-01-01T00:00:00+01:00', end_date: null }))
      .toEqual({ relativeDate: null, startDate: '2026-01-01T00:00:00+01:00', endDate: null });
  });

  it('should keep the other config keys', () => {
    expect(applyPublicationTimeRange(config, { relative_date: 'days-7' })).toEqual({ ...config, relativeDate: 'days-7' });
  });

  it('should accept a relative date the time filters do not offer', () => {
    expect(applyPublicationTimeRange({}, { relative_date: 'days-30' })).toEqual({ relativeDate: 'days-30', startDate: null, endDate: null });
  });

  it.each([
    { relative_date: 'weeks-2' },
    { relative_date: 'days-' },
    { relative_date: 'days-99999' },
    { start_date: '2026/01/01' },
    { end_date: '2026-02-30' },
  ])('should refuse an unknown relative date or a malformed date (%o)', (range) => {
    expect(() => applyPublicationTimeRange({}, range)).toThrow('Invalid public dashboard time range');
  });
});

describe('toPublicationTimeZone', () => {
  it('should keep a supported time zone', () => {
    expect(toPublicationTimeZone('Europe/Paris')).toEqual('Europe/Paris');
  });

  it.each(['', null, undefined])('should fall back to UTC without time zone (%o)', (timeZone) => {
    expect(toPublicationTimeZone(timeZone)).toBeUndefined();
  });

  it('should refuse an unsupported time zone rather than silently counting in UTC', () => {
    expect(() => toPublicationTimeZone('Mars/Olympus')).toThrow('Invalid public dashboard time zone');
  });
});
