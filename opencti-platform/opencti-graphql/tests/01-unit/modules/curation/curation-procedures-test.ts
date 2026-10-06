import { describe, expect, it } from 'vitest';
import { procedureNoteInput } from '../../../../src/modules/curation/curation-procedures';

describe('Curation relationship conflicts - note mode', () => {
  const relationship = { internal_id: 'rel-1', fromName: 'APT28', toName: 'Spearphishing Attachment', markingIds: ['marking-1'] };

  it('keeps the overwritten procedure in a note attached to the relationship, with its markings', () => {
    expect(procedureNoteInput(relationship, 'Uses spearphishing attachments', null)).toEqual({
      attribute_abstract: 'Alternative procedure: APT28 uses Spearphishing Attachment',
      content: 'Uses spearphishing attachments',
      note_types: ['analysis'],
      objects: ['rel-1'],
      objectMarking: ['marking-1'],
    });
  });

  it('sets the author only when the writer of the procedure is an identity', () => {
    expect(procedureNoteInput(relationship, 'Uses spearphishing attachments', 'identity-1').createdBy).toBe('identity-1');
    expect('createdBy' in procedureNoteInput(relationship, 'Uses spearphishing attachments', null)).toBe(false);
  });
});
