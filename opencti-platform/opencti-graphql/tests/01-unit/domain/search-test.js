import { expect, it } from 'vitest';
import { adaptFilterToIdsFilterKey, buildLocalMustFilter, elGenerateFullTextSearchShould, specialElasticCharsEscape } from '../../../src/database/engine';
import { isNotEmptyField } from '../../../src/database/utils';

const parse = (search) => {
  const shouldSearch = elGenerateFullTextSearchShould(search);
  expect(shouldSearch.length).toBeGreaterThan(1);
  const queriesString = shouldSearch
    .map((e) => e?.query_string?.query)
    .filter((f) => isNotEmptyField(f))
    .join(' ');
  const matchesString = shouldSearch
    .map((e) => e?.multi_match?.query)
    .filter((f) => isNotEmptyField(f))
    .join(' ');
  return { queriesString, matchesString };
};

it('should string correctly escaped', async () => {
  // +|\-*()~={}:?\\
  let escape = specialElasticCharsEscape('Looking {for} [malware] : ~APT');
  expect(escape).toEqual('Looking \\{for\\} \\[malware\\] \\: \\~APT');
  escape = specialElasticCharsEscape('Looking (threat) = ?maybe');
  expect(escape).toEqual('Looking \\(threat\\) \\= \\?maybe');
  escape = specialElasticCharsEscape('Looking All* + Everything| - \\with');
  expect(escape).toEqual('Looking All\\* \\+ Everything\\| \\- \\\\with');
});

it('should search parsing correctly generated', () => {
  // URL TESTING
  let parsed = parse('first http://localhost:4000/graphql');
  expect(parsed.queriesString).toBe('first* http\\:\\/\\/localhost\\:4000\\/graphql*');
  expect(parsed.matchesString).toBe('first* http\\:\\/\\/localhost\\:4000\\/graphql*');

  parsed = parse('https://localhost:4000/graphql second');
  expect(parsed.queriesString).toBe('https\\:\\/\\/localhost\\:4000\\/graphql* second*');
  expect(parsed.matchesString).toBe('https\\:\\/\\/localhost\\:4000\\/graphql* second*');

  // GENERIC TESTING
  parsed = parse('(Citation:');
  expect(parsed.queriesString).toBe('\\(Citation\\:*');
  expect(parsed.matchesString).toBe('\\(Citation\\:*');

  parsed = parse('        """""coucou"  ');
  expect(parsed.queriesString).toBe('');
  expect(parsed.matchesString).toBe('coucou');

  parsed = parse('        "test search        fs       ');
  expect(parsed.queriesString).toBe('test* search* fs*');
  expect(parsed.matchesString).toBe('test* search* fs*');

  parsed = parse('test test search "please my" "bad');
  expect(parsed.queriesString).toBe('test* search* bad*');
  expect(parsed.matchesString).toBe('please my test* search* bad*');

  parsed = parse('cool test-with');
  expect(parsed.queriesString).toBe('cool* test\\-with*');
  expect(parsed.matchesString).toBe('cool* test\\-with*');

  parsed = parse('test of search with $"()_"!spe")£")cif2933920ic chars');
  expect(parsed.queriesString).toBe('test* of* search* with* $\\!spe\\)cif2933920ic* chars*');
  expect(parsed.matchesString).toBe('()_ )£ test* of* search* with* $\\!spe\\)cif2933920ic* chars*');

  // IDS TESTING
  parsed = parse('     test       d1d7344e-f38e-497b-930c-07779d81ffff');
  expect(parsed.queriesString).toBe('test* d1d7344e\\-f38e\\-497b\\-930c\\-07779d81ffff*');
  expect(parsed.matchesString).toBe('test* d1d7344e\\-f38e\\-497b\\-930c\\-07779d81ffff*');

  parsed = parse('identity--21985175-7f18-589d-a078-ad14116a0efc');
  expect(parsed.queriesString).toBe('identity\\-\\-21985175\\-7f18\\-589d\\-a078\\-ad14116a0efc*');
  expect(parsed.matchesString).toBe('identity\\-\\-21985175\\-7f18\\-589d\\-a078\\-ad14116a0efc*');

  parsed = parse('"identity--21985175-7f18-589d-a078-ad14116a0efc"');
  expect(parsed.queriesString).toBe('');
  expect(parsed.matchesString).toBe('identity--21985175-7f18-589d-a078-ad14116a0efc');
});

it('should buildLocalMustFilter build query from ids filter with terms', () => {
  const { newFilter } = adaptFilterToIdsFilterKey({ key: 'ids', values: ['ID1', 'ID2', 'ID3'] });
  const query = buildLocalMustFilter(newFilter);
  const expectedQuery = {
    bool: {
      should: [
        { terms: { 'internal_id.keyword': ['ID1', 'ID2', 'ID3'] } },
        { terms: { 'standard_id.keyword': ['ID1', 'ID2', 'ID3'] } },
        { terms: { 'x_opencti_stix_ids.keyword': ['ID1', 'ID2', 'ID3'] } },
        { terms: { 'i_aliases_ids.keyword': ['ID1', 'ID2', 'ID3'] } }],
      minimum_should_match: 1 }
  };
  expect(query).toEqual(expectedQuery);
});
