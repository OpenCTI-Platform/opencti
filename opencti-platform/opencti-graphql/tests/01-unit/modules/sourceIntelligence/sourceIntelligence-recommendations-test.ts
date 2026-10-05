import { describe, expect, it } from 'vitest';
import '../../../../src/modules/index';
import { assertTargetUnchanged, restoresStatusAfterUnrecordedApply, undoLeavesNothing } from '../../../../src/modules/sourceIntelligence/sourceIntelligence-recommendations';
import { RECOMMENDATION_ADD_CONNECTOR, RECOMMENDATION_CHANGE_SCHEDULE, RECOMMENDATION_KINDS } from '../../../../src/modules/sourceIntelligence/sourceIntelligence-types';

describe('Source intelligence recommendations', () => {
  it('should refuse a change whose target moved since the proposal, and accept an unchanged one', () => {
    expect(() => assertTargetUnchanged('schedule of the feed', 'PT1H', 'PT1H')).not.toThrow();
    // Proposals recorded before the check carry no previewed value
    expect(() => assertTargetUnchanged('schedule of the feed', undefined, 'PT4H')).not.toThrow();
    expect(() => assertTargetUnchanged('schedule of the feed', 'PT1H', 'PT4H')).toThrow('changed since this recommendation was proposed (PT1H, now PT4H)');
    expect(() => assertTargetUnchanged('max confidence of the source user', 75, 60)).toThrow('nothing was changed');
  });

  it('should never offer to apply again a recommendation whose undo leaves a deployed connector behind', () => {
    expect(undoLeavesNothing(RECOMMENDATION_ADD_CONNECTOR)).toBe(false);
  });

  it('should offer to apply again the other kinds once undone', () => {
    RECOMMENDATION_KINDS.filter((kind) => kind !== RECOMMENDATION_ADD_CONNECTOR).forEach((kind) => {
      expect(undoLeavesNothing(kind)).toBe(true);
    });
  });

  it('should keep a recommendation retryable when an apply that wrote nothing cannot be recorded', () => {
    // Failed or succeeded before writing anything: nothing to undo, every kind can be applied again
    RECOMMENDATION_KINDS.forEach((kind) => {
      expect(restoresStatusAfterUnrecordedApply(false, false, kind)).toBe(true);
    });
    // After a write: only once undone, and never when the undo leaves a deployed connector behind
    expect(restoresStatusAfterUnrecordedApply(true, true, RECOMMENDATION_CHANGE_SCHEDULE)).toBe(true);
    expect(restoresStatusAfterUnrecordedApply(true, true, RECOMMENDATION_ADD_CONNECTOR)).toBe(false);
    expect(restoresStatusAfterUnrecordedApply(true, false, RECOMMENDATION_CHANGE_SCHEDULE)).toBe(false);
  });
});
