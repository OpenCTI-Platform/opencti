import { find, propEq, map } from 'ramda';
import {
  elIsAlive,
  elPaginate,
  elVersion,
  forceNoCache,
  INDEX_STIX_ENTITIES
} from '../../../src/database/elasticSearch';

describe('Elasticsearch testing', () => {
  it('should configuration correct', () => {
    expect(elIsAlive()).resolves.toBeTruthy();
    expect(elVersion()).resolves.toContain('7.5');
    expect(forceNoCache()).toBeFalsy();
  });

  it('should elastic accessible', async () => {
    const data = await elPaginate(INDEX_STIX_ENTITIES, { types: ['Malware'] });
    expect(data).not.toBeNull();
    expect(data.edges.length).toBeGreaterThanOrEqual(2);
    const nodes = map(e => e.node, data.edges);
    const malware = find(propEq('stix_id_key', 'malware--c521e7de-aeb9-439b-8bb3-cd93a88f27ea'))(nodes);
    expect(malware.internal_id_key).not.toBeNull();
    expect(malware.name).toEqual('Beacon');
    // eslint-disable-next-line no-underscore-dangle
    expect(malware._index).toEqual(INDEX_STIX_ENTITIES);
    expect(malware.parent_types).toEqual(expect.arrayContaining(['Malware', 'Stix-Domain-Entity', 'Stix-Domain']));
  });
});
