import { afterAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { buildViewParamsFromUrlAndStorage } from './ListParameters';

describe('ListParameters utils', () => {
  let mockNavigate: ReturnType<typeof vi.fn>;
  let mockLocation: { pathname: string; search: string };

  beforeEach(() => {
    mockNavigate = vi.fn();
    mockLocation = {
      pathname: '/test',
      search: '',
    };
    localStorage.clear();
  });

  afterAll(() => {
    localStorage.clear();
  });

  describe(buildViewParamsFromUrlAndStorage, () => {
    it('should convert comma-separated string from URL to array', () => {
      mockLocation.search = '?disabledEntityTypes=Malware,Indicator,Report';
      
      const result = buildViewParamsFromUrlAndStorage(
        mockNavigate,
        mockLocation,
        'test-key'
      );

      expect(result.disabledEntityTypes).toEqual(['Malware', 'Indicator', 'Report']);
    });

    it('should convert localStorage string values to arrays (backward compatibility)', () => {
      localStorage.setItem('test-key', JSON.stringify({
        disabledEntityTypes: 'toto,tutu',
        disabledCreators: 'creator1',
        disabledMarkings: 'marking1,marking2,marking3'
      }));
      
      mockLocation.search = '';
      
      const result = buildViewParamsFromUrlAndStorage(
        mockNavigate,
        mockLocation,
        'test-key'
      );

      expect(result.disabledEntityTypes).toEqual(['toto', 'tutu']);
      expect(result.disabledCreators).toEqual(['creator1']);
      expect(result.disabledMarkings).toEqual(['marking1', 'marking2', 'marking3']);
    });

    it('should return empty array when URL parameter value is empty string', () => {
      mockLocation.search = '?disabledEntityTypes=';
      
      const result = buildViewParamsFromUrlAndStorage(
        mockNavigate,
        mockLocation,
        'test-key'
      );

      expect(result.disabledEntityTypes).toEqual([]);
    });

    it('should convert single value to single-element array', () => {
      mockLocation.search = '?disabledEntityTypes=Malware';
      
      const result = buildViewParamsFromUrlAndStorage(
        mockNavigate,
        mockLocation,
        'test-key'
      );

      expect(result.disabledEntityTypes).toEqual(['Malware']);
    });

    it('should give URL parameters priority over localStorage', () => {
      localStorage.setItem('test-key', JSON.stringify({
        disabledEntityTypes: ['toto', 'tutu']
      }));

      mockLocation.search = '?disabledEntityTypes=Malware,Indicator';
      
      const result = buildViewParamsFromUrlAndStorage(
        mockNavigate,
        mockLocation,
        'test-key'
      );

      expect(result.disabledEntityTypes).toEqual(['Malware', 'Indicator']);
    });

    it('should handle missing parameters without errors', () => {
      mockLocation.search = '?otherParam=value';
      
      expect(() => {
        buildViewParamsFromUrlAndStorage(
          mockNavigate,
          mockLocation,
          'test-key'
        );
      }).not.toThrow();
    });
  });
});
