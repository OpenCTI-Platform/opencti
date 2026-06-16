import { graphql } from 'react-relay';
import type { FilterGroup } from '../../../../utils/filters/filtersHelpers-types';
import type { enrollPlaybookDrawerIdsQuery$data } from './__generated__/enrollPlaybookDrawerIdsQuery.graphql';
import type { enrollPlaybookDrawerFiltersQuery$data } from './__generated__/enrollPlaybookDrawerFiltersQuery.graphql';

export const playbooksForEnrollmentIdsQuery = graphql`
  query enrollPlaybookDrawerIdsQuery($ids: [String!]!) {
    playbooksForEnrollment(ids: $ids) {
      id
      name
      description
    }
  }
`;

export const playbooksForEnrollmentByFiltersQuery = graphql`
  query enrollPlaybookDrawerFiltersQuery($filters: FilterGroup, $search: String, $excludedIds: [String!]) {
    playbooksForEnrollmentByFilters(filters: $filters, search: $search, excludedIds: $excludedIds) {
      id
      name
      description
    }
  }
`;

export interface Playbook {
  label: string;
  value: string;
  description: string | null | undefined;
}

export type IdsResponseData = enrollPlaybookDrawerIdsQuery$data;
export type FiltersResponseData = enrollPlaybookDrawerFiltersQuery$data;

export interface FetchPlaybooksParams {
  isSelectAll?: boolean;
  filters?: FilterGroup | null;
  search?: string | null;
  excludedIds?: string[];
  entityIds?: string[];
}

export type Fetcher = (query: unknown, variables: Record<string, unknown>) => Promise<unknown>;

export function mapIdsResponse(data: IdsResponseData): Playbook[] {
  return (data.playbooksForEnrollment ?? [])
    .filter((p): p is NonNullable<typeof p> => Boolean(p))
    .map((p) => ({
      label: p.name,
      value: p.id,
      description: p.description,
    }));
}

export function mapFiltersResponse(data: FiltersResponseData): Playbook[] {
  return data.playbooksForEnrollmentByFilters
    .filter((p): p is NonNullable<typeof p> => Boolean(p))
    .map((p) => ({
      label: p.name,
      value: p.id,
      description: p.description,
    }));
}

export function sortPlaybooks(playbooks: Playbook[]): Playbook[] {
  return [...playbooks].sort((a, b) => a.label.localeCompare(b.label));
}

export async function fetchPlaybooks(params: FetchPlaybooksParams, fetcher: Fetcher): Promise<Playbook[]> {
  if (params.isSelectAll) {
    const response = await fetcher(playbooksForEnrollmentByFiltersQuery, {
      filters: params.filters ?? undefined,
      search: params.search ?? undefined,
      excludedIds: params.excludedIds ?? [],
    });
    return sortPlaybooks(mapFiltersResponse(response as FiltersResponseData));
  }

  const response = await fetcher(playbooksForEnrollmentIdsQuery, {
    ids: params.entityIds ?? [],
  });
  return sortPlaybooks(mapIdsResponse(response as IdsResponseData));
}
