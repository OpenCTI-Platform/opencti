import React, { FunctionComponent, ReactElement, ReactNode } from 'react';
import { Option } from '../../private/components/common/form/ReferenceField';

export interface DataColumn {
  isSortable: boolean;
  label: string;
  width?: string | number;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  render?: (v: any) => ReactNode;
}
export type DataColumns = Record<string, DataColumn>;

export type Filters<F = Record<string, unknown>[]> = Record<string, F>;

export enum OrderMode {
  asc = 'asc',
  desc = 'desc',
}

export interface PaginationOptions {
  toId?: string;
  search?: string;
  orderBy?: string;
  orderMode?: OrderMode;
  filters?: Filters;
}

export type ListLines = FunctionComponent<unknown>;

export type RenderOption = (
  props: React.AllHTMLAttributes<never>,
  { value, description }: Option
) => ReactElement;
