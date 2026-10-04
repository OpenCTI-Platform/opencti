import { describe, expect, it } from 'vitest';
import '../../../../src/modules/index';
import { undoLeavesNothing } from '../../../../src/modules/sourceIntelligence/sourceIntelligence-recommendations';
import { RECOMMENDATION_ADD_CONNECTOR, RECOMMENDATION_KINDS } from '../../../../src/modules/sourceIntelligence/sourceIntelligence-types';

describe('Source intelligence recommendations', () => {
  it('should never offer to apply again a recommendation whose undo leaves a deployed connector behind', () => {
    expect(undoLeavesNothing(RECOMMENDATION_ADD_CONNECTOR)).toBe(false);
  });

  it('should offer to apply again the other kinds once undone', () => {
    RECOMMENDATION_KINDS.filter((kind) => kind !== RECOMMENDATION_ADD_CONNECTOR).forEach((kind) => {
      expect(undoLeavesNothing(kind)).toBe(true);
    });
  });
});
