import { describe, expect, it, beforeEach, afterEach } from 'vitest';
import setStackDataInSessionStorage from './setStackDataInSessionStorage';

describe('Session Storage', () => {
  describe('setStackDataInSessionStorage', () => {
    const testKey = 'testKey';
    const stackValue = 2;

    afterEach(() => {
      sessionStorage.removeItem('testKey');
    });

    describe('When I set a data in session storage', () => {
      beforeEach(() => {
        setStackDataInSessionStorage(testKey, { test: 'value1' }, stackValue);
      });

      describe('If I get datas with my key from session storage', () => {
        it('contains my value', () => {
          const storedData = sessionStorage.getItem('testKey');
          expect(storedData).not.toBeNull();

          if (storedData) {
            const parsedStoredData = JSON.parse(storedData);
            expect(parsedStoredData[0].test).toEqual('value1');
          }
        });
      });
    });

    describe('When I set three data in session storage with a stack value of 2', () => {
      beforeEach(() => {
        Array.from(Array(3).keys()).forEach((_, i) => {
          setStackDataInSessionStorage(testKey, { test: `value${i}` }, stackValue);
        });
      });

      describe('If I get datas with my key from session storage', () => {
        it('does not contains my first value', () => {
          const storedData = sessionStorage.getItem('testKey');
          expect(storedData).not.toBeNull();

          if (storedData) {
            const parsedStoredData = JSON.parse(storedData);
            expect(parsedStoredData[2]).toBeUndefined();
          }
        });

        it('contains my two last values', () => {
          const storedData = sessionStorage.getItem('testKey');
          expect(storedData).not.toBeNull();

          if (storedData) {
            const parsedStoredData = JSON.parse(storedData);
            expect(parsedStoredData[0].test).toEqual('value2');
            expect(parsedStoredData[1].test).toEqual('value1');
            expect(parsedStoredData[2]).toBeUndefined();
          }
        });
      });
    });
  });
});
