import { describe, expect, it } from 'vitest';
import { prepareElementForIndexing } from '../../../src/database/engine';
import { ENTITY_TYPE_CONTAINER_OPINION, ENTITY_TYPE_INDICATOR } from '../../../src/schema/stixDomainObject';
import '../../../src/modules/index';
import { ENTITY_HASHED_OBSERVABLE_ARTIFACT } from '../../../src/schema/stixCyberObservable';

describe('prepareElementForIndexing testing', () => {
  it('should base trim applied', () => {
    const element = prepareElementForIndexing({ entity_type: ENTITY_TYPE_INDICATOR, name: '  test' });
    expect(element.name).toBe('test');
  });
  it('should numeric and boolean prepared', () => {
    const element = prepareElementForIndexing({ entity_type: ENTITY_TYPE_INDICATOR, x_opencti_score: 10, x_opencti_detection: 'false' });
    expect(element.x_opencti_score).toBe(10);
    expect(element.x_opencti_detection).toBe(false);
  });
  it('should dic prepared (inner trim)', () => {
    const element = prepareElementForIndexing({ entity_type: ENTITY_HASHED_OBSERVABLE_ARTIFACT, hashes: { MD5: '   MD5   ', SHA1: '   SHA1   ' } });
    expect(element.hashes.MD5).toBe('MD5');
    expect(element.hashes.SHA1).toBe('SHA1');
  });
  it('should array trim applied', () => {
    const element = prepareElementForIndexing({ entity_type: ENTITY_TYPE_CONTAINER_OPINION, authors: ['  trim01  ', '  trim 02    '] });
    expect(element.authors).toEqual(['trim01', 'trim 02']);
  });
  it('should inner array trim applied', () => {
    const prepare = () => prepareElementForIndexing({ entity_type: ENTITY_TYPE_CONTAINER_OPINION, authors: [20, '  trim01  ', '  trim 02    '] });
    expect(prepare).toThrow();
  });
  it('should do nothing with date value', () => {
    const now = new Date();
    const element = prepareElementForIndexing({ date: now });
    expect(element.date).toEqual(now);
  });
});
