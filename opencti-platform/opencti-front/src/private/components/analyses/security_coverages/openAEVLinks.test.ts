import { describe, expect, it } from 'vitest';
import { distinctOpenAEVLinks } from './openAEVLinks';

const SCENARIO = 'https://ctem.oaev.example.io/tenant/admin/scenarios/d320df42';

describe('distinctOpenAEVLinks', () => {
  it('returns nothing without an external URI', () => {
    expect(distinctOpenAEVLinks(null)).toEqual([]);
    expect(distinctOpenAEVLinks([{ name: 'a', external_uri: null }, { name: 'b', external_uri: '  ' }])).toEqual([]);
  });

  it('collapses results that share one OpenAEV link into a single entry', () => {
    const links = distinctOpenAEVLinks([
      { name: 'Coverage', external_uri: SCENARIO },
      { name: 'Coverage again', external_uri: SCENARIO },
    ]);
    expect(links).toEqual([{ url: SCENARIO, host: 'ctem.oaev.example.io', label: 'Coverage' }]);
  });

  it('keeps one entry per distinct link, labelled by name or host', () => {
    const links = distinctOpenAEVLinks([
      { name: 'Coverage', external_uri: SCENARIO },
      { name: '', external_uri: 'https://other.oaev.example.io/admin/scenarios/1' },
    ]);
    expect(links.map((l) => l.label)).toEqual(['Coverage', 'other.oaev.example.io']);
  });
});
