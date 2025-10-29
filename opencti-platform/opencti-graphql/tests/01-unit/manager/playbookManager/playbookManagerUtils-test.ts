import { describe, expect, it } from 'vitest';
import { isValidEventType } from '../../../../src/manager/playbookManager/playbookManagerUtils';

describe('playbookManagerUtils', () => {
  describe('isValidEventType', () => {
    describe('When evenType is correct and corresponding event in configuration is true', () => {
      it('should return true', () => {
        const result = isValidEventType('create', { create: true });
        expect(result).toBeTruthy();
      });
    });

    describe('When evenType is correct but corresponding event in configuration is false', () => {
      it('should return false', () => {
        const result = isValidEventType('create', { create: false });
        expect(result).toBeFalsy();
      });
    });
  });
});
