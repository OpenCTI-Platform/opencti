import { describe, expect, it } from 'vitest';
import { xtmCardAnchorKey } from './xtmCardAnchorKey';

describe('xtmCardAnchorKey', () => {
  it('places the card after the later of Details and Basic information, above Notes', () => {
    expect(xtmCardAnchorKey([
      { key: 'details' },
      { key: 'basicInformation' },
      { key: 'latestCreatedRelationships' },
      { key: 'notes' },
    ])).toBe('basicInformation');
    expect(xtmCardAnchorKey([{ key: 'basicInformation' }, { key: 'details' }, { key: 'notes' }])).toBe('details');
  });

  it('has no anchor when the layout shows neither, so the card closes the grid', () => {
    expect(xtmCardAnchorKey([{ key: 'notes' }])).toBeNull();
  });
});
