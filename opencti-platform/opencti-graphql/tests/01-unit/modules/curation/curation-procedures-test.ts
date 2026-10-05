import { describe, expect, it } from 'vitest';
import { procedureAdditions, procedureNoteInput } from '../../../../src/modules/curation/curation-procedures';

const AT = '2026-10-03T20:00:00.000Z';

describe('Curation relationship conflicts - procedures', () => {
  it('appends both conflicting descriptions, trimmed, with their writers', () => {
    const additions = procedureAdditions([], [
      { text: '  Uses spearphishing attachments ', source_id: 'user-a' },
      { text: 'Uses spearphishing links', source_id: 'user-b' },
    ], AT);
    expect(additions).toEqual([
      { text: 'Uses spearphishing attachments', source_id: 'user-a', last_asserted_at: AT },
      { text: 'Uses spearphishing links', source_id: 'user-b', last_asserted_at: AT },
    ]);
  });

  it('never adds a procedure already known, whatever its case or surrounding spaces', () => {
    const additions = procedureAdditions([{ text: 'Uses spearphishing attachments' }], [
      { text: 'uses SPEARPHISHING attachments  ', source_id: 'user-a' },
      { text: 'Uses spearphishing links', source_id: 'user-b' },
      { text: 'USES spearphishing links', source_id: 'user-c' },
    ], AT);
    expect(additions).toEqual([{ text: 'Uses spearphishing links', source_id: 'user-b', last_asserted_at: AT }]);
  });

  it('ignores empty or missing descriptions', () => {
    expect(procedureAdditions([{ text: null }], [null, undefined, { text: '   ', source_id: 'user-a' }], AT)).toEqual([]);
  });
});

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
