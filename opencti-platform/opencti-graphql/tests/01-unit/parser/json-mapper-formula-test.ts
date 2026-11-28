import { describe, expect, it } from 'vitest';
import { checkJsonMapperFormula } from '../../../src/parser/json-mapper-formula';

describe('JSON mapper formula check', () => {
  it.each([
    'patternFromValue("IPv4-Addr", ip)',
    'extractWithRegexp("^(\\\\d+)", 1, value)',
    'decisionMatrix(level, 50, [{ value: "high", result: 90 }])',
    'name ? name.toUpperCase() : "unknown"',
    'a?.b ?? `${c}-${d}`',
    '[1, 2].map((x) => x * 2).join(",")',
    '(() => { const a = name; return a; })()',
    'name;',
    'name // note',
    '/* note */ name',
    'name\n',
    '  ',
  ])('should accept "%s"', (formula) => {
    expect(() => checkJsonMapperFormula(formula)).not.toThrow();
  });

  it.each([null, undefined])('should accept a missing formula (%s)', (formula) => {
    expect(() => checkJsonMapperFormula(formula)).not.toThrow();
  });

  it.each([
    ['a closing delimiter', 'a ?> b'],
    ['an opening delimiter', 'x <? y'],
    ['a delimiter in a string', '"?>"'],
    ['two expressions', '1); (2'],
    ['two statements', 'let y = 2; y'],
    ['two lines', 'a\nb'],
    ['a declaration', 'function f() {}'],
    ['a block', '{ a: 1 }'],
    ['two semicolons', 'name;;'],
    ['only a comment', '// note'],
    ['invalid javascript', 'name('],
    ['not a string', 42],
  ])('should refuse %s', (_, formula) => {
    expect(() => checkJsonMapperFormula(formula)).toThrow();
  });
});
