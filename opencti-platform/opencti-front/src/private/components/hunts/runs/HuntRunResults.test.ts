import { describe, expect, it } from 'vitest';
import { resolveLink } from '../../../../utils/Entity';
import { huntRunResultLink } from './HuntRunResults';

describe('huntRunResultLink', () => {
  it('should link an object with a route of its own', () => {
    expect(huntRunResultLink({ id: 'sighting-1', entity_type: 'stix-sighting-relationship' }))
      .toEqual(`${resolveLink('stix-sighting-relationship')}/sighting-1`);
  });

  it('should link a relationship without a route under its source entity', () => {
    const relationship = { id: 'rel-1', entity_type: 'uses', from: { id: 'set-1', entity_type: 'Intrusion-Set' } };
    expect(huntRunResultLink(relationship)).toEqual(`${resolveLink('Intrusion-Set')}/set-1/knowledge/relations/rel-1`);
  });

  it('should give no link when neither the result nor its source has a route', () => {
    expect(huntRunResultLink({ id: 'rel-2', entity_type: 'uses' })).toBeNull();
    expect(huntRunResultLink({ id: 'rel-3', entity_type: 'uses', from: { id: 'x', entity_type: 'Unknown-Type' } })).toBeNull();
  });
});
