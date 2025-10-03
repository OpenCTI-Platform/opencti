import { describe, it, expect } from 'vitest';
import { isValidLatitude, isValidLongitude, getValidatedCenter, validateCoordinates, DEFAULT_CENTER_COORDINATES } from './position.utils';

describe('Position utils', () => {
  describe('getValidatedCenter', () => {
    it('should handle invalid coordinates from bug #11841', () => {
      // Test the exact bug case
      const position = { latitude: -1171507146, longitude: 150 };
      expect(getValidatedCenter(position)).toEqual(DEFAULT_CENTER_COORDINATES);
    });

    it('should return valid coordinates', () => {
      const position = { latitude: 45.5, longitude: -73.6 };
      expect(getValidatedCenter(position)).toEqual([45.5, -73.6]);
    });

    it('should handle null and undefined values', () => {
      expect(getValidatedCenter({ latitude: null, longitude: null })).toEqual(DEFAULT_CENTER_COORDINATES);
      expect(getValidatedCenter({ latitude: undefined, longitude: undefined })).toEqual(DEFAULT_CENTER_COORDINATES);
      expect(getValidatedCenter({})).toEqual(DEFAULT_CENTER_COORDINATES);
    });
  });

  describe('validateCoordinates', () => {
    it('should validate array format', () => {
      expect(validateCoordinates([48.8, 2.3])).toEqual([48.8, 2.3]);
      expect(validateCoordinates([-1171507146, 150])).toEqual(DEFAULT_CENTER_COORDINATES);
      expect(validateCoordinates(null)).toEqual(DEFAULT_CENTER_COORDINATES);
      expect(validateCoordinates([45])).toEqual(DEFAULT_CENTER_COORDINATES);
    });
  });

  describe('isValidLatitude and isValidLongitude', () => {
    it('should validate latitude range', () => {
      expect(isValidLatitude(45)).toBe(true);
      expect(isValidLatitude(-90)).toBe(true);
      expect(isValidLatitude(90)).toBe(true);
      expect(isValidLatitude(-1171507146)).toBe(false);
      expect(isValidLatitude(91)).toBe(false);
      expect(isValidLatitude(null)).toBe(false);
    });

    it('should validate longitude range', () => {
      expect(isValidLongitude(150)).toBe(true);
      expect(isValidLongitude(-180)).toBe(true);
      expect(isValidLongitude(180)).toBe(true);
      expect(isValidLongitude(181)).toBe(false);
      expect(isValidLongitude(null)).toBe(false);
    });
  });
});
