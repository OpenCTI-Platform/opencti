import { graknIsAlive, load } from '../../../src/database/grakn';

describe('Database init', () => {
  it('should database accessible', () => {
    expect(graknIsAlive()).toBeTruthy();
  });
});

describe('Grakn basic loader', () => {
  it('should load simple query', async () => {
    const query = 'match $m isa Malware; $m has stix_id_key "malware--c6006dd5-31ca-45c2-8ae0-4e428e712f88"; get;';
    const malware = await load(query, ['m'], { noCache: true });
    expect(malware.m).not.toBeNull();
    expect(malware.m.stix_id_key).toEqual('malware--c6006dd5-31ca-45c2-8ae0-4e428e712f88');
  });
});
