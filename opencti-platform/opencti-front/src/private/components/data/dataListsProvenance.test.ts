import { describe, expect, it } from 'vitest';
import { entitiesDataColumns } from './Entities';
import { relationshipsDataColumns } from './Relationships';

describe('Data lists and the provenance switch', () => {
  it('should show the corroboration column only while provenance is enabled', () => {
    expect(Object.keys(entitiesDataColumns(false, true))).toContain('corroboration_count');
    expect(Object.keys(relationshipsDataColumns(false, true))).toContain('corroboration_count');
    expect(Object.keys(entitiesDataColumns(false, false))).not.toContain('corroboration_count');
    expect(Object.keys(relationshipsDataColumns(false, false))).not.toContain('corroboration_count');
  });

  it('should keep the layout of a platform without provenance while it is disabled', () => {
    expect(entitiesDataColumns(true, false)).toEqual({
      entity_type: { percentWidth: 13 },
      name: {},
      createdBy: { isSortable: true },
      creator: { isSortable: true },
      objectLabel: {},
      created_at: {},
      objectMarking: { isSortable: true },
    });
    expect(relationshipsDataColumns(true, false)).toEqual({
      fromType: {},
      fromName: {},
      relationship_type: {},
      toType: {},
      toName: {},
      createdBy: { percentWidth: 7, isSortable: true },
      creator: { percentWidth: 7, isSortable: true },
      created_at: { percentWidth: 12 },
      objectMarking: { isSortable: true },
    });
  });
});
