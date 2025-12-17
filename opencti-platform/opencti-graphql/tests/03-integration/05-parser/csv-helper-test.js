import { describe, expect, it } from 'vitest';
import { columnNameToIdx, extractValueFromCsv } from '../../../src/parser/csv-helper';

describe('CSV-HELPER', () => {
  describe('columnNameToIdx()', () => {
    it('should return -1 if empty string', () => {
      expect(columnNameToIdx('')).toBe(-1);
    });

    it('should return -1 if invalid name', () => {
      expect(columnNameToIdx('!!')).toBe(-1);
      expect(columnNameToIdx('A!')).toBe(-1);
      expect(columnNameToIdx('5')).toBe(-1);
      expect(columnNameToIdx('5BC')).toBe(-1);
    });

    it('should return correct index', () => {
      expect(columnNameToIdx('')).toBe(-1);
      expect(columnNameToIdx('A')).toBe(0); // A=0
      expect(columnNameToIdx('Z')).toBe(25); // Z=25
      expect(columnNameToIdx('AD')).toBe(29); // A=0 D=3 => 1*26 + 3 => 29
      expect(columnNameToIdx('BE')).toBe(56); // B=1 E=4 => 2*26 + 4 => 56
      expect(columnNameToIdx('IQ')).toBe(250); // I=8 Q=16 => 9*26 + 16 => 250
      expect(columnNameToIdx('AJD')).toBe(939);
    });
  });

  describe('extractValueFromCsv()', () => {
    const records = ['hello', 'super', 'world'];

    it('should throw an error if invalid name', () => {
      const call = () => extractValueFromCsv(records, '!A@B');
      expect(call).toThrowError(/Unknown column name/);
    });

    it('should return the correct record', () => {
      expect(extractValueFromCsv(records, 'A')).toBe('hello');
      expect(extractValueFromCsv(records, 'B')).toBe('super');
      expect(extractValueFromCsv(records, 'C')).toBe('world');
      expect(extractValueFromCsv(records, 'D')).toBe(undefined);
    });
  });
});
