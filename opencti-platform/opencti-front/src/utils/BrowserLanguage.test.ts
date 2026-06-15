import { describe, it, expect } from 'vitest';
import { LANGUAGES, DEFAULT_LANG, detectedLocale } from './BrowserLanguage';

describe('BrowserLanguage utils', () => {
  describe('LANGUAGES constant', () => {
    it('should define languages correctly', () => {
      expect(LANGUAGES.CHINESE).toBe('zh-cn');
      expect(LANGUAGES.ENGLISH).toBe('en-us');
      expect(LANGUAGES.FRENCH).toBe('fr-fr');
    });
  });

  describe('DEFAULT_LANG constant', () => {
    it('should fall back to English by default', () => {
      expect(DEFAULT_LANG).toBe('en-us');
    });
  });

  describe('Function: detectedLocale', () => {
    it('should return undefined if navigator is null or undefined', () => {
      expect(detectedLocale(null)).toBeUndefined();
      expect(detectedLocale(undefined)).toBeUndefined();
    });

    it('should return undefined if navigator has no language keys', () => {
      expect(detectedLocale({})).toBeUndefined();
    });

    it('should match language from languages array', () => {
      const mockNav = {
        languages: ['fr-FR', 'en-US'],
      };
      expect(detectedLocale(mockNav)).toBe('fr-fr');
    });

    it('should match language from language property', () => {
      const mockNav = {
        language: 'zh-CN',
      };
      expect(detectedLocale(mockNav)).toBe('zh-cn');
    });

    it('should match language from browserLanguage property', () => {
      const mockNav = {
        browserLanguage: 'DE-DE',
      } as unknown as Navigator;
      expect(detectedLocale(mockNav)).toBe('de-de');
    });

    it('should match language from userLanguage property', () => {
      const mockNav = {
        userLanguage: 'ES-ES',
      } as unknown as Navigator;
      expect(detectedLocale(mockNav)).toBe('es-es');
    });

    it('should match language from systemLanguage property', () => {
      const mockNav = {
        systemLanguage: 'IT-IT',
      } as unknown as Navigator;
      expect(detectedLocale(mockNav)).toBe('it-it');
    });

    it('should return undefined if none of the languages are supported', () => {
      const mockNav = {
        languages: ['ru-RU', 'pl-PL'],
      };
      expect(detectedLocale(mockNav)).toBeUndefined();
    });
  });
});
