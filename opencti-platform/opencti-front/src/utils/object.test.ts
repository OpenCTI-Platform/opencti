import { describe, it, expect } from 'vitest';
import { getObjectPropertyWithoutEmptyValues } from './object';

describe('Utils: getObjectPropertyWithoutEmptyValues', () => {
  it('should display readable attribute', () => {
    const object = {
      id: 'XXX',
      name: 'myReport',
      representative: {
        main: 'myReport',
        description: '',
      },
      report_types: ['type1', 'type2'],
      objectLabel: [
        { value: 'label1', color: 'red' },
        { value: 'label2', color: 'green' },
      ],
      objectMarking: [],
      createdBy: null,
      modified: null,
      externalReferences: [
        { url: 'http://test.com', standard_id: 'externalRef1' },
        { url: null, standard_id: 'externalRef2' },
      ],
    };

    const stringProperty = getObjectPropertyWithoutEmptyValues(object, 'name');
    expect(stringProperty).toEqual('myReport');
    const nullProperty = getObjectPropertyWithoutEmptyValues(object, 'modified');
    expect(nullProperty).toEqual('');
    const listProperty = getObjectPropertyWithoutEmptyValues(object, 'report_types');
    expect(listProperty).toEqual(['type1', 'type2']);
    const propertyWithPath = getObjectPropertyWithoutEmptyValues(object, 'representative.main');
    expect(propertyWithPath).toEqual('myReport');
    const listPropertyWithPath = getObjectPropertyWithoutEmptyValues(object, 'objectLabel.value');
    expect(listPropertyWithPath).toEqual(['label1', 'label2']);
    const invalidPathProperty = () => getObjectPropertyWithoutEmptyValues(object, 'createdBy.name');
    expect(invalidPathProperty).toThrowError('Invalid path "createdBy.name", a subpart is not an object');
    const listPropertyWithNullValues = getObjectPropertyWithoutEmptyValues(object, 'externalReferences.url');
    expect(listPropertyWithNullValues).toEqual(['http://test.com']);
  });

  it('should resolve null subparts as empty only when nullableSubparts is set', () => {
    const object = {
      name: 'myReport',
      createdBy: null,
      objectLabel: [{ value: 'label1' }, null],
    };

    expect(() => getObjectPropertyWithoutEmptyValues(object, 'createdBy.name')).toThrow('a subpart is not an object');
    expect(getObjectPropertyWithoutEmptyValues(object, 'createdBy.name', { nullableSubparts: true })).toEqual('');
    expect(getObjectPropertyWithoutEmptyValues(object, 'objectLabel.value', { nullableSubparts: true })).toEqual(['label1']);
    expect(() => getObjectPropertyWithoutEmptyValues(object, 'name.value', { nullableSubparts: true })).toThrow('a subpart is not an object');
  });
});
