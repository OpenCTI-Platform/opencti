import { elSearchParser, specialElasticCharsEscape } from '../../../src/database/elasticSearch';

const parse = (search) => {
  const { search: field, attributeFields, connectionFields } = elSearchParser(search);
  expect(attributeFields.length).toBeGreaterThan(1);
  expect(connectionFields.length).toBeGreaterThanOrEqual(1);
  return field;
};

test('should string correctly escaped', async () => {
  // +|\-*()~={}:?\\
  let escape = specialElasticCharsEscape('Looking {for} [malware] : ~APT');
  expect(escape).toEqual('Looking \\{for\\} \\[malware\\] \\: \\~APT');
  escape = specialElasticCharsEscape('Looking (threat) = ?maybe');
  expect(escape).toEqual('Looking \\(threat\\) \\= \\?maybe');
  escape = specialElasticCharsEscape('Looking All* + Everything| - \\with');
  expect(escape).toEqual('Looking All\\* \\+ Everything\\| - \\\\with');
});

test('should search parsing correctly generated', () => {
  // URL TESTING
  expect(parse('first http://localhost:4000/graphql')) //
    .toBe('"*localhost\\:4000/graphql*" *first*');
  expect(parse('https://localhost:4000/graphql second')) //
    .toBe('"*localhost\\:4000/graphql*" *second*');
  // GENERIC TESTING
  expect(parse('        """""coucou"  ')) //
    .toBe('"coucou"');
  expect(parse(' first- - test - after')) //
    .toBe('"*-*" "*first-*" *after* *test*');
  expect(parse('        "test search        fs       ')) //
    .toBe('*fs* *search* *test*');
  expect(parse('test test search "please my" "bad')) //
    .toBe('"please my" *bad* *search* *test*');
  expect(parse('cool test-with')) //
    .toBe('"*test-with*" *cool*');
  expect(parse('test of search with $"()_"!spe")£")cif2933920ic chars')) //
    .toBe('"\\(\\)_" "\\)£" *$!spe\\)cif2933920ic* *chars* *of* *search* *test* *with*');
  // IDS TESTING
  expect(parse('     test       d1d7344e-f38e-497b-930c-07779d81ffff')) //
    .toBe('"d1d7344e-f38e-497b-930c-07779d81ffff" *test*');
  expect(parse('identity--21985175-7f18-589d-a078-ad14116a0efc')) //
    .toBe('"identity--21985175-7f18-589d-a078-ad14116a0efc"');
});
