import { beforeEach, describe, expect, it, vi } from 'vitest';
import resolvers from '../../../src/resolvers/stixObjectOrStixRelationshipOrCreator';

describe('StixRelationship.representative resolver', () => {
  const load = vi.fn();
  const context = { batch: { idsBatchLoader: { load } } };
  const relationship = {
    entity_type: 'uses',
    fromId: 'from-id',
    fromType: 'Indicator',
    fromName: 'visible indicator',
    toId: 'to-id',
    toType: 'Malware',
    toName: 'secret malware',
    description: 'a description',
  };
  const resolve = (rel: object) => resolvers.StixRelationship.representative(rel, {}, context);

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('keeps the stored names when both endpoints are accessible', async () => {
    load.mockResolvedValue({ id: 'accessible' });
    expect(await resolve(relationship)).toEqual({ main: 'visible indicator ➡️ secret malware', secondary: 'a description' });
    expect(load).toHaveBeenCalledWith({ id: 'from-id', type: 'Indicator' });
    expect(load).toHaveBeenCalledWith({ id: 'to-id', type: 'Malware' });
  });

  it('redacts the name of an endpoint the user cannot access', async () => {
    load.mockImplementation(async ({ id }) => (id === 'from-id' ? { id } : undefined));
    expect((await resolve(relationship)).main).toEqual('visible indicator ➡️ Restricted');
    load.mockImplementation(async ({ id }) => (id === 'to-id' ? { id } : undefined));
    expect((await resolve(relationship)).main).toEqual('Restricted ➡️ secret malware');
  });

  it('redacts both endpoints when none is accessible, keeping the description', async () => {
    load.mockResolvedValue(undefined);
    expect(await resolve(relationship)).toEqual({ main: 'Restricted ➡️ Restricted', secondary: 'a description' });
  });

  it('does not load an endpoint already resolved, nor a representative already given', async () => {
    expect((await resolve({ ...relationship, from: { id: 'from-id' }, to: { id: 'to-id' } })).main).toEqual('visible indicator ➡️ secret malware');
    expect(load).not.toHaveBeenCalled();
    const given = { main: 'Restricted', secondary: 'Restricted' };
    expect(await resolve({ ...relationship, representative: given })).toEqual(given);
    expect(load).not.toHaveBeenCalled();
  });
});
