import { describe, expect, it } from 'vitest';
import { OrderMode } from '../../components/list_lines';
import { localStorageToPaginationOptions } from './useLocalStorage';

describe('localStorageToPaginationOptions', () => {
  it('should not set orderBy/orderMode when sortBy is undefined', () => {
    const result = localStorageToPaginationOptions({
      orderAsc: false,
      sortBy: undefined,
    });
    expect(result.orderBy).toBeUndefined();
    expect(result.orderMode).toBeUndefined();
  });

  it('should set orderBy and orderMode desc when sortBy is defined and orderAsc is false', () => {
    const result = localStorageToPaginationOptions({
      sortBy: 'name',
      orderAsc: false,
    });
    expect(result.orderBy).toBe('name');
    expect(result.orderMode).toBe(OrderMode.desc);
  });

  it('should set orderBy and orderMode asc when sortBy is defined and orderAsc is true', () => {
    const result = localStorageToPaginationOptions({
      sortBy: 'name',
      orderAsc: true,
    });
    expect(result.orderBy).toBe('name');
    expect(result.orderMode).toBe(OrderMode.asc);
  });
});
