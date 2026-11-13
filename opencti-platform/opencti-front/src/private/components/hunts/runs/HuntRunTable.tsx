import React, { CSSProperties, useState } from 'react';
import { Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import DataTableWithoutFragment from '../../../../components/dataGrid/DataTableWithoutFragment';
import { DataTableProps, DataTableVariant } from '../../../../components/dataGrid/dataTableTypes';
import { SELECT_COLUMN_SIZE } from '../../../../components/dataGrid/components/DataTableHeader';
import { defaultRender } from '../../../../components/dataGrid/dataTableUtils';
import { useFormatter } from '../../../../components/i18n';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';

// A line of the data table is 48 px high with a 1 px border under it
const ROW_HEIGHT = 49;
// A longer table scrolls inside its card instead of stretching the page
const MAX_VISIBLE_ROWS = 15;

export interface HuntRunTableSort {
  sortBy?: string;
  orderAsc: boolean;
}

/** The sort of a table of the run page, kept in the local storage of the table as the lists keep theirs. */
export const useHuntRunTableSort = (storageKey: string, initialValues: HuntRunTableSort) => {
  const { viewStorage, helpers } = usePaginationLocalStorage(storageKey, initialValues, true);
  return {
    sortBy: viewStorage.sortBy ?? initialValues.sortBy,
    orderAsc: viewStorage.orderAsc ?? initialValues.orderAsc,
    initialValues,
    onSort: helpers.handleSort,
  };
};

export type HuntRunSortValue = string | number | null | undefined;

/** The rows in the order of one column, empty values last in both orders; rows of the same value keep their order. */
export const sortHuntRunRows = <T,>(rows: ReadonlyArray<T>, value: ((row: T) => HuntRunSortValue) | undefined, orderAsc: boolean): T[] => {
  if (!value) {
    return [...rows];
  }
  return [...rows].sort((a, b) => {
    const left = value(a);
    const right = value(b);
    const leftEmpty = left === null || left === undefined || left === '';
    const rightEmpty = right === null || right === undefined || right === '';
    if (leftEmpty || rightEmpty) {
      return Number(leftEmpty) - Number(rightEmpty);
    }
    const result = typeof left === 'number' && typeof right === 'number' ? left - right : String(left).localeCompare(String(right));
    return orderAsc ? result : -result;
  });
};

/** A value that may be cut by its column, readable whole in its tooltip. */
export const HuntRunCut = ({ value, full, style }: { value: string; full?: string; style?: CSSProperties }) => (
  <Tooltip>
    <TooltipTrigger asChild>
      <span style={{ display: 'block', minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', ...style }}>{value}</span>
    </TooltipTrigger>
    <TooltipContent>{full ?? value}</TooltipContent>
  </Tooltip>
);

/** A text cell, empty when the value was not recorded. */
export const huntRunTextCell = (value?: string | null) => (value ? defaultRender(value) : '');

/** A date in the short form of the tables, its full date and time in the tooltip; empty when not recorded. */
export const HuntRunDateCell = ({ date }: { date?: string | null }) => {
  const { fldt, mhd } = useFormatter();
  return date ? <HuntRunCut value={mhd(date)} full={fldt(date)} /> : null;
};

type HuntRunTableProps = Pick<DataTableProps, 'dataColumns' | 'getComputeLink' | 'disableNavigation' | 'onSort'> & {
  storageKey: string;
  initialValues: HuntRunTableSort;
  rows: ReadonlyArray<{ id: string }>;
  label: string;
  testId: string;
};

/** A table of the run page: the data table of the lists, as high as its rows up to a bound, then scrolling. */
const HuntRunTable = ({ storageKey, initialValues, rows, label, testId, ...tableProps }: HuntRunTableProps) => {
  const [element, setElement] = useState<HTMLDivElement | null>(null);
  const height = SELECT_COLUMN_SIZE + Math.min(Math.max(rows.length, 1), MAX_VISIBLE_ROWS) * ROW_HEIGHT;
  return (
    <div ref={setElement} style={{ height }} role="region" aria-label={label} data-testid={testId}>
      {element && (
        <DataTableWithoutFragment
          {...tableProps}
          storageKey={storageKey}
          initialValues={initialValues}
          rootRef={element}
          variant={DataTableVariant.inline}
          data={rows}
          globalCount={rows.length}
          pageSize={String(Math.max(rows.length, 1))}
          disableLineSelection
          disableToolBar
          removeSelectAll
        />
      )}
    </div>
  );
};

export default HuntRunTable;
