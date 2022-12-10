import { FunctionComponent } from 'react';

export interface DataColumn { isSortable: boolean, label: string, width?: string | number }
export type DataColumns = Record<string, DataColumn>;

export type Filters<F = Record<string, unknown>[]> = Record<string, F>;

export enum OrderMode {
  asc = 'asc',
  desc = 'desc',
}

export interface PaginationOptions {
  fromRole?: unknown,
  toId?: unknown,
  search?: string,
  orderBy?: string,
  orderMode?: OrderMode,
  filters?: Filters,
}

export type ListLines = FunctionComponent<unknown>;
