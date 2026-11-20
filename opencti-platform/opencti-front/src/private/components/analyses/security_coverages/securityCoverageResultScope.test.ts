import { describe, it, expect } from 'vitest';
import { ALL_RESULTS_VALUE, buildResultOptions, buildResultScopeVariables, buildScopeRefreshKey, resolveSelectedResult, toResultId } from './securityCoverageResultScope';

describe('securityCoverageResultScope', () => {
  const paris = { id: 'scr-paris', name: 'OAEV Paris', external_uri: 'https://paris' };
  const lyon = { id: 'scr-lyon', name: 'OAEV Lyon', external_uri: 'https://lyon' };

  it('keeps the order of the results', () => {
    expect(buildResultOptions([paris, lyon]).map((o) => o.label)).toEqual(['OAEV Paris', 'OAEV Lyon']);
  });
  it('disambiguates duplicated names with the external uri, then the id', () => {
    const a = { id: 'scr-a', name: 'Result of SC', external_uri: 'https://a' };
    const b = { id: 'scr-b', name: 'Result of SC', external_uri: null };
    expect(buildResultOptions([a, b])).toEqual([
      { value: 'scr-a', label: 'Result of SC – https://a' },
      { value: 'scr-b', label: 'Result of SC – scr-b' },
    ]);
  });
  it('falls back to the id when the name and the external uri are both shared', () => {
    const a = { id: 'scr-a', name: 'Result of SC', external_uri: 'https://a' };
    const b = { id: 'scr-b', name: 'Result of SC', external_uri: 'https://a' };
    expect(buildResultOptions([a, b]).map((o) => o.label)).toEqual(['Result of SC – scr-a', 'Result of SC – scr-b']);
  });
  it('disambiguates three results with the same name', () => {
    const securityCoverageResults = [
      { id: 'scr-a', name: 'Result of SC', external_uri: 'https://a' },
      { id: 'scr-b', name: 'Result of SC', external_uri: 'https://b' },
      { id: 'scr-c', name: 'Result of SC', external_uri: null },
    ];
    expect(buildResultOptions(securityCoverageResults).map((o) => o.label)).toEqual([
      'Result of SC – https://a',
      'Result of SC – https://b',
      'Result of SC – scr-c',
    ]);
  });
  it('falls back to the id when the external uri is empty', () => {
    const a = { id: 'scr-a', name: 'Result of SC', external_uri: '' };
    const b = { id: 'scr-b', name: 'Result of SC', external_uri: 'https://b' };
    expect(buildResultOptions([a, b]).map((o) => o.label)).toEqual(['Result of SC – scr-a', 'Result of SC – https://b']);
  });
  it('maps the all-results value to no result', () => {
    expect(toResultId(ALL_RESULTS_VALUE)).toBeNull();
    expect(toResultId('scr-paris')).toBe('scr-paris');
  });
  it('resolves the selected result, or null when it is gone', () => {
    expect(resolveSelectedResult([paris, lyon], 'scr-lyon')).toBe(lyon);
    expect(resolveSelectedResult([paris], 'scr-lyon')).toBeNull();
    expect(resolveSelectedResult([paris], null)).toBeNull();
  });
  it('builds query variables scoped to one result', () => {
    expect(buildResultScopeVariables('sc-1', 'scr-paris')).toEqual({
      id: 'sc-1',
      filters: { mode: 'and', filters: [{ key: ['fromId'], values: ['scr-paris'], operator: 'eq', mode: 'or' }], filterGroups: [] },
      fromId: ['scr-paris'],
    });
  });
  it('changes the refresh key when the coverage or one of its results is updated', () => {
    const base = buildScopeRefreshKey('2026-11-19T10:00:00Z', [{ id: 'scr-paris', coverage_last_result: '2026-11-18T10:00:00Z' }]);
    expect(buildScopeRefreshKey('2026-11-19T10:00:00Z', [{ id: 'scr-paris', coverage_last_result: '2026-11-18T10:00:00Z' }])).toBe(base);
    expect(buildScopeRefreshKey('2026-11-19T11:00:00Z', [{ id: 'scr-paris', coverage_last_result: '2026-11-18T10:00:00Z' }])).not.toBe(base);
    expect(buildScopeRefreshKey('2026-11-19T10:00:00Z', [{ id: 'scr-paris', coverage_last_result: '2026-11-19T09:00:00Z' }])).not.toBe(base);
    expect(buildScopeRefreshKey('2026-11-19T10:00:00Z', [])).not.toBe(base);
  });
  it('gives the same refresh key for a null and an undefined last result', () => {
    expect(buildScopeRefreshKey('2026-11-19T10:00:00Z', [{ id: 'scr-paris', coverage_last_result: null }]))
      .toBe(buildScopeRefreshKey('2026-11-19T10:00:00Z', [{ id: 'scr-paris' }]));
  });
  it('changes the refresh key when a result is removed', () => {
    const both = buildScopeRefreshKey('2026-11-19T10:00:00Z', [{ id: 'scr-paris' }, { id: 'scr-lyon' }]);
    expect(buildScopeRefreshKey('2026-11-19T10:00:00Z', [{ id: 'scr-paris' }])).not.toBe(both);
  });
});
