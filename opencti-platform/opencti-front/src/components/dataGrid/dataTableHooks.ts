import { useFragment } from 'react-relay';
import type { GraphQLTaggedNode, OperationType } from 'relay-runtime';
import type { KeyType } from 'react-relay/relay-hooks/helpers';
import { DataTableColumn, DataTableVariant, UseDataTable } from './dataTableTypes';
import usePreloadedPaginationFragment, { UsePreloadedPaginationFragment } from '../../utils/hooks/usePreloadedPaginationFragment';
import { useFormatter } from '../i18n';
import useEntityToggle from '../../utils/hooks/useEntityToggle';
import { computeLink } from '../../utils/Entity';
import useLocalStorage, { UseLocalStorageHelpers } from '../../utils/hooks/useLocalStorage';

export const useLineData = (lineFragment: GraphQLTaggedNode) => (row: KeyType) => useFragment(lineFragment, row);

export const useDataTable = (args: UsePreloadedPaginationFragment<OperationType>): UseDataTable => usePreloadedPaginationFragment(args) as UseDataTable;

export const useDataCellHelpers = (storageHelpers: UseLocalStorageHelpers | Record<string, unknown>, variant: DataTableVariant) => (column: DataTableColumn) => {
  const formatterHelper = useFormatter();
  return {
    ...formatterHelper,
    storageHelpers,
    column,
    variant,
  };
};

export const useDataTableToggle = useEntityToggle;

export const useComputeLink = computeLink;

export const useDataTableLocalStorage = useLocalStorage;
