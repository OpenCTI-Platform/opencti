import { describe, expect, it } from 'vitest';
import { engineMappingGenerator, prepareDataFromSchemaDefinition } from '../../../src/database/engine';
import { ENTITY_TYPE_CONTAINER_OPINION, ENTITY_TYPE_INDICATOR } from '../../../src/schema/stixDomainObject';
import '../../../src/modules/index';
import { ENTITY_HASHED_OBSERVABLE_ARTIFACT } from '../../../src/schema/stixCyberObservable';
import { ENTITY_TYPE_CONNECTOR, ENTITY_TYPE_GROUP } from '../../../src/schema/internalObject';

describe('prepareDataFromSchemaDefinition testing', () => {
  it('should base trim applied', () => {
    const element = prepareDataFromSchemaDefinition({ entity_type: ENTITY_TYPE_INDICATOR, name: '  test' });
    expect(element.name).toBe('test');
  });
  it('should numeric and boolean prepared', () => {
    const element = prepareDataFromSchemaDefinition({ entity_type: ENTITY_TYPE_INDICATOR, x_opencti_score: 10, x_opencti_detection: false });
    expect(element.x_opencti_score).toBe(10);
    expect(element.x_opencti_detection).toBe(false);
  });
  it('should numeric and boolean prepared from string', () => {
    const element = prepareDataFromSchemaDefinition({ entity_type: ENTITY_TYPE_INDICATOR, x_opencti_score: '10', x_opencti_detection: 'false' });
    expect(element.x_opencti_score).toBe(10);
    expect(element.x_opencti_detection).toBe(false);
  });
  it('should incorrect type throw', () => {
    const prepare = () => prepareDataFromSchemaDefinition({ entity_type: ENTITY_TYPE_INDICATOR, x_opencti_score: {}, x_opencti_detection: 'false' });
    expect(prepare).toThrow();
  });
  it.skip('should dic prepared (inner trim)', () => {
    const element = prepareDataFromSchemaDefinition({ entity_type: ENTITY_HASHED_OBSERVABLE_ARTIFACT, hashes: { MD5: '   MD5   ', SHA1: '   SHA1   ' } });
    expect(element.hashes.MD5).toBe('MD5');
    expect(element.hashes.SHA1).toBe('SHA1');
  });
  it('should array trim applied', () => {
    const element = prepareDataFromSchemaDefinition({ entity_type: ENTITY_TYPE_CONTAINER_OPINION, authors: ['  trim01  ', '  trim 02    '] });
    expect(element.authors).toEqual(['trim01', 'trim 02']);
  });
  it('should multiple different types correctly throw', () => {
    const prepare = () => prepareDataFromSchemaDefinition({ entity_type: ENTITY_TYPE_CONTAINER_OPINION, authors: [20, '  trim01  ', '  trim 02    '] });
    expect(prepare).toThrow();
  });
  it('should object correctly checked', () => {
    const emptyElement = prepareDataFromSchemaDefinition({ entity_type: ENTITY_TYPE_GROUP, default_marking: [{}, {}] });
    expect(emptyElement.default_marking).toEqual([]);
    const dataElement = prepareDataFromSchemaDefinition({ entity_type: ENTITY_TYPE_GROUP, default_marking: [{ test: 1 }, { test: 2 }] });
    expect(dataElement.default_marking).toEqual([{ test: 1 }, { test: 2 }]);
    const mixedElement = () => prepareDataFromSchemaDefinition({ entity_type: ENTITY_TYPE_GROUP, default_marking: [{ test: 1 }, 'test'] });
    expect(mixedElement).toThrow();
    const invalidObjectElement = () => prepareDataFromSchemaDefinition({ entity_type: ENTITY_TYPE_GROUP, default_marking: {} });
    expect(invalidObjectElement).toThrow();
    const invalidStringElement = () => prepareDataFromSchemaDefinition({ entity_type: ENTITY_TYPE_GROUP, default_marking: 'test' });
    expect(invalidStringElement).toThrow();
    const innerElement = () => prepareDataFromSchemaDefinition({ entity_type: ENTITY_TYPE_GROUP, default_marking: ['test01', 'test02'] });
    expect(innerElement).toThrow();
  });
  it('should json correctly checked', () => {
    const emptyElement = prepareDataFromSchemaDefinition({ entity_type: ENTITY_TYPE_CONNECTOR, connector_state: '' });
    expect(emptyElement.connector_state).toEqual('{}');
    const objectElement = prepareDataFromSchemaDefinition({ entity_type: ENTITY_TYPE_CONNECTOR, connector_state: { state: 'state' } });
    expect(objectElement.connector_state).toEqual('{"state":"state"}');
    const objectListElement = prepareDataFromSchemaDefinition({ entity_type: ENTITY_TYPE_CONNECTOR, connector_state: ['test'] });
    expect(objectListElement.connector_state).toEqual('["test"]');
    const stringElement = () => prepareDataFromSchemaDefinition({ entity_type: ENTITY_TYPE_CONNECTOR, connector_state: 'test' });
    expect(stringElement).toThrow();
  });
  it('should engine schema correctly generated', () => {
    const schema = engineMappingGenerator();
    expect(Object.keys(schema).length).toEqual(505);
  });
});
