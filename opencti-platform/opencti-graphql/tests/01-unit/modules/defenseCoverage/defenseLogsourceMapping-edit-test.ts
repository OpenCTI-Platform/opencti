import { describe, expect, it } from 'vitest';
import { EditOperation } from '../../../../src/generated/graphql';
import { cleanDataComponentNames, normalizeMappingEditInputs } from '../../../../src/modules/defenseCoverage/defenseLogsourceMapping/defenseLogsourceMapping-domain';

describe('Log source mapping edition', () => {
  it('should replace the data components with their cleaned names', () => {
    const input = [
      { key: 'data_components', value: [' Process Creation ', 'Process Creation', null, 'Command Execution'] },
      { key: 'description', value: ['Updated'], operation: EditOperation.Replace },
      { key: 'active', value: [false] },
    ];
    expect(normalizeMappingEditInputs(input)).toEqual([
      { key: 'data_components', value: ['Process Creation', 'Command Execution'] },
      { key: 'description', value: ['Updated'], operation: EditOperation.Replace },
      { key: 'active', value: [false] },
    ]);
  });

  it.each([
    ['an added value', { key: 'data_components', value: ['Process Creation'], operation: EditOperation.Add }],
    ['a removed value', { key: 'data_components', value: ['Process Creation'], operation: EditOperation.Remove }],
    ['an object path', { key: 'description', value: ['Updated'], object_path: '/description' }],
  ])('should refuse %s', (_, edit) => {
    expect(() => normalizeMappingEditInputs([edit])).toThrow('A log source mapping is updated by replacing its values, without operation or object path');
  });

  it.each([
    ['a number', [12]],
    ['an object', [{ name: 'Process Creation' }]],
    ['a list', [['Process Creation']]],
  ])('should refuse a data component given as %s', (_, value) => {
    expect(() => normalizeMappingEditInputs([{ key: 'data_components', value }])).toThrow('The data components of a log source mapping must be texts');
  });

  it('should refuse a mapping left without data components', () => {
    expect(() => normalizeMappingEditInputs([{ key: 'data_components', value: [] }])).toThrow('A log source mapping requires at least one data component');
    expect(() => cleanDataComponentNames([' ', null])).toThrow('A log source mapping requires at least one data component');
  });
});
