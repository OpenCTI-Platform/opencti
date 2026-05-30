import { graphql } from 'react-relay';
import { fetchQuery } from '../../../relay/environment';
import type { caseRfiNodeIdsApiQuery$data } from './__generated__/caseRfiNodeIdsApiQuery.graphql';

const caseRfiNodeIdsQuery = graphql`
  query caseRfiNodeIdsApiQuery(
    $count: Int
    $filters: FilterGroup
  ) {
    caseRfis(
      first: $count
      orderBy: created
      orderMode: desc
      filters: $filters
    ) {
      edges {
        node {
          id
        }
      }
    }
  }
`;

export const CASE_RFI_LIST_FILTERS = {
  mode: 'and',
  filters: [{
    key: 'entity_type',
    values: ['Case-Rfi'],
    operator: 'eq',
    mode: 'or',
  }],
  filterGroups: [],
};

export const fetchCaseRfiNodeIds = async (count: number = 25): Promise<string[]> => {
  const data = await fetchQuery(caseRfiNodeIdsQuery, {
    count,
    filters: CASE_RFI_LIST_FILTERS,
  }).toPromise();

  const response = data as caseRfiNodeIdsApiQuery$data;
  return (response.caseRfis?.edges ?? [])
    .map((edge) => edge?.node?.id)
    .filter((id): id is string => typeof id === 'string');
};
