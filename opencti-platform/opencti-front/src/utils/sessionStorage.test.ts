import { describe, expect, it, afterEach } from 'vitest';
import { addInSessionStorageStack, getSessionStorageItem, setSessionStorageItem } from './sessionStorage';

describe('Session storage utils', () => {
  const testKey = 'test-session-storage';

  afterEach(() => {
    sessionStorage.removeItem(testKey);
  });

  describe('setSessionStorageItem()', () => {
    it('should save the value for the given key', () => {
      setSessionStorageItem(testKey, 'hello there');
      const storedData = sessionStorage.getItem(testKey);
      expect(storedData).not.toBeNull();
      expect(storedData).toEqual('"hello there"');
    });
  });

  describe('getSessionStorageItem()', () => {
    it('should return null if no data for the key', () => {
      const storedData = getSessionStorageItem('invalid_key');
      expect(storedData).toBeNull();
    });

    it('should retrieve the value for the given key (string)', () => {
      setSessionStorageItem(testKey, 'hello there');
      const storedData = getSessionStorageItem(testKey);
      expect(storedData).not.toBeNull();
      expect(storedData).toEqual('hello there');
    });

    it('should retrieve the value for the given key (object)', () => {
      setSessionStorageItem(testKey, { hello: 'hello there' });
      const storedData = getSessionStorageItem(testKey);
      expect(storedData).not.toBeNull();
      expect(storedData).toEqual({ hello: 'hello there' });
    });
  });

  describe('addInSessionStorageStack()', () => {
    it('should add item in stack and keep max size', () => {
      const stackSize = 2;

      addInSessionStorageStack(testKey, '1', stackSize);
      let storedData = getSessionStorageItem(testKey);
      expect(storedData).toEqual(['1']);

      addInSessionStorageStack(testKey, '2', stackSize);
      storedData = getSessionStorageItem(testKey);
      expect(storedData).toEqual(['2', '1']);

      addInSessionStorageStack(testKey, '3', stackSize);
      storedData = getSessionStorageItem(testKey);
      expect(storedData).toEqual(['3', '2']);
    });
  });
});
