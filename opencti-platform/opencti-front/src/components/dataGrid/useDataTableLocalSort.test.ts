import { describe, it, expect } from 'vitest';
import { sort } from './useDataTableLocalSort';

describe('useDataTableLocalSort', () => {
  describe('sort', () => {
    it('sorts strings ASC', () => {
      const data = [{
        name: 'C',
      }, {
        name: 'A',
      }, {
        name: 'b',
      }];
      const sortedData = sort(data, 'name', true);
      expect(sortedData).toMatchObject([{
        name: 'A',
      }, {
        name: 'b',
      }, {
        name: 'C',
      }]);
    });

    it('sorts strings DESC', () => {
      const data = [{
        name: 'C',
      }, {
        name: 'A',
      }, {
        name: 'b',
      }];
      const sortedData = sort(data, 'name', false);
      expect(sortedData).toMatchObject([{
        name: 'C',
      }, {
        name: 'b',
      }, {
        name: 'A',
      }]);
    });

    it('sorts numbers ASC', () => {
      const data = [{
        idx: 100,
      }, {
        idx: 1,
      }, {
        idx: 20,
      }];
      const sortedData = sort(data, 'idx', true);
      expect(sortedData).toMatchObject([{
        idx: 1,
      }, {
        idx: 20,
      }, {
        idx: 100,
      }]);
    });

    it('sorts numbers DESC', () => {
      const data = [{
        idx: 100,
      }, {
        idx: 1,
      }, {
        idx: 20,
      }];
      const sortedData = sort(data, 'idx', false);
      expect(sortedData).toMatchObject([{
        idx: 100,
      }, {
        idx: 20,
      }, {
        idx: 1,
      }]);
    });

    it('sorts booleans ASC', () => {
      const data = [{
        isGood: true,
      }, {
        isGood: false,
      }, {
        isGood: true,
      }];
      const sortedData = sort(data, 'isGood', true);
      expect(sortedData).toMatchObject([{
        isGood: false,
      }, {
        isGood: true,
      }, {
        isGood: true,
      }]);
    });

    it('sorts booleans DESC', () => {
      const data = [{
        isGood: true,
      }, {
        isGood: false,
      }, {
        isGood: true,
      }];
      const sortedData = sort(data, 'isGood', false);
      expect(sortedData).toMatchObject([{
        isGood: true,
      }, {
        isGood: true,
      }, {
        isGood: false,
      }]);
    });
  });
});
