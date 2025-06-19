import React, { FunctionComponent, ReactElement, ReactNode } from 'react';
import { FilterGroup } from '../../utils/filters/filtersHelpers-types';
import { FieldOption } from '../../utils/field';

interface ListLineOption extends FieldOption {
  description: ReactNode
}

export interface DataColumn {
  isSortable: boolean;
  label: string;
  width?: string | number;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  render?: (v: any, helpers?: any) => ReactNode;
}

export type DataColumns = Record<string, DataColumn>;

export enum OrderMode {
  asc = 'asc',
  desc = 'desc',
}

export interface PaginationOptions {
  toId?: string | string[]
  fromId?: string[]
  toTypes?: string[]
  fromTypes?: string[]
  search?: string | null
  orderBy?: string | null
  orderMode?: OrderMode | null
  filters?: FilterGroup
  pageSize?: string
}

export type ListLines = FunctionComponent<unknown>;

export type RenderOption = (
  props: React.AllHTMLAttributes<never>,
  { value, description }: ListLineOption
) => ReactElement;
