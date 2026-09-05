import { describe, expect, it } from 'vitest';
import {
  findRegisterRow,
  registerRowsByDisposition,
  USER_MERGE_REGISTER,
  USER_MERGE_REGISTER_VERSION,
  UserMergeDisposition,
} from '../../../../src/modules/userMerge/userMerge-register';

/**
 * The v5 baseline, transcribed from the register page. It is asserted here rather than
 * derived from the constant: a test that recounts the array would agree with any
 * transcription mistake it is supposed to catch.
 */
const V5_DISTRIBUTION: Record<UserMergeDisposition, number> = {
  [UserMergeDisposition.Transfer]: 41,
  [UserMergeDisposition.Invalidate]: 20,
  [UserMergeDisposition.Conditional]: 21,
  [UserMergeDisposition.Retain]: 11,
  [UserMergeDisposition.OutOfScope]: 6,
};

describe('User merge register', () => {
  it('should be pinned to the v5 registry version', () => {
    expect(USER_MERGE_REGISTER_VERSION).toBe('v5');
  });

  it('should match the v5 distribution, disposition by disposition', () => {
    Object.entries(V5_DISTRIBUTION).forEach(([disposition, expectedCount]) => {
      const rows = registerRowsByDisposition(disposition as UserMergeDisposition);
      expect(rows.length, `disposition ${disposition}`).toBe(expectedCount);
    });
  });

  it('should hold exactly 99 rows, and no row outside the known dispositions', () => {
    const total = Object.values(V5_DISTRIBUTION).reduce((acc, count) => acc + count, 0);
    expect(USER_MERGE_REGISTER.length).toBe(total);
  });

  it('should carry unique row ids', () => {
    const ids = USER_MERGE_REGISTER.map((entry) => entry.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it('should describe every row: id, entity and path are all filled', () => {
    USER_MERGE_REGISTER.forEach((entry) => {
      expect(entry.id.length, `row ${entry.id} has an empty id`).toBeGreaterThan(0);
      expect(entry.label.length, `row ${entry.id} has an empty label`).toBeGreaterThan(0);
      expect(entry.path.length, `row ${entry.id} has an empty path`).toBeGreaterThan(0);
    });
  });

  it('should resolve a row by id, and reject an unknown one', () => {
    expect(findRegisterRow('basic-object.creator-id')?.disposition).toBe(UserMergeDisposition.Transfer);
    expect(findRegisterRow('user.password')?.disposition).toBe(UserMergeDisposition.Invalidate);
    expect(findRegisterRow('no-such-row')).toBeUndefined();
  });
});
