import { useMemo } from 'react';
import type { LocalStorage } from '../../utils/hooks/useLocalStorageModel';
import { useDataTablePaginationLocalStorage } from './dataTableHooks';

type SortableData = ReadonlyArray<Record<string, string | number | boolean>>;

export const sort = (data: SortableData, sortBy: string, orderAsc: boolean) =>
  [...data].sort((lhs, rhs) => {
    if (typeof lhs[sortBy] === 'string' && typeof rhs[sortBy] === 'string') {
      const lhsValue = lhs[sortBy].toLocaleLowerCase();
      const rhsValue = rhs[sortBy].toLocaleLowerCase();
      return orderAsc
        ? lhsValue.localeCompare(rhsValue)
        : rhsValue.localeCompare(lhsValue);
    } else if (typeof lhs[sortBy] === 'number' && typeof rhs[sortBy] === 'number') {
      return (orderAsc ? 1 : -1) * (lhs[sortBy] - rhs[sortBy]);
    } else if (typeof lhs[sortBy] === 'boolean' && typeof rhs[sortBy] === 'boolean') {
      return (orderAsc ? 1 : -1) * (Number(lhs[sortBy]) - Number(rhs[sortBy]));
    }
    // Mixed types are unhandled
    return 0;
  });

interface UseClientSideDataTableSortProps {
  data: SortableData;
  storageKey: string;
  initialValues: Required<Pick<LocalStorage, 'orderAsc' | 'sortBy'>>;
}

const useDataTableLocalSort = ({ data, storageKey, initialValues }: UseClientSideDataTableSortProps) => {
  const { viewStorage } = useDataTablePaginationLocalStorage(
    storageKey,
    initialValues,
    true,
  );
  const { sortBy, orderAsc } = viewStorage;

  const sortedData = useMemo(() =>
    sort(
      data,
      sortBy ?? initialValues.sortBy,
      orderAsc ?? initialValues.orderAsc,
    ), [data, sortBy, orderAsc],
  );
  return { sortedData };
};

export default useDataTableLocalSort;
