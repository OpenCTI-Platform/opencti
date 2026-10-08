import { graphql, useLazyLoadQuery } from 'react-relay';
import { useCurationPendingCountQuery } from './__generated__/useCurationPendingCountQuery.graphql';

const curationPendingCountQuery = graphql`
  query useCurationPendingCountQuery($filters: FilterGroup) {
    curationProposals(first: 1, filters: $filters) {
      pageInfo {
        globalCount
      }
    }
  }
`;

const OPEN_PROPOSALS = {
  mode: 'and',
  filters: [{ key: ['proposal_status'], values: ['open'], operator: 'eq', mode: 'or' }],
  filterGroups: [],
} as const;

/** The proposals waiting for a decision: the badge of the Inbox tab and its share of the Curation menu badge. */
const useCurationPendingCount = (retry = 0) => {
  const { curationProposals } = useLazyLoadQuery<useCurationPendingCountQuery>(
    curationPendingCountQuery,
    { filters: OPEN_PROPOSALS },
    { fetchPolicy: 'store-and-network', fetchKey: retry },
  );
  return curationProposals?.pageInfo.globalCount ?? null;
};

export default useCurationPendingCount;
