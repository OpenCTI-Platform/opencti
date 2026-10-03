import { graphql } from 'react-relay';
import { useNavigate } from 'react-router';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import type { useGraphAnalyticsInvestigationMutation } from './__generated__/useGraphAnalyticsInvestigationMutation.graphql';
import { type GraphAnalyticsPivotKind, recordGraphAnalyticsPivot } from './graphAnalyticsUtils';

const startInvestigationMutation = graphql`
  mutation useGraphAnalyticsInvestigationMutation($input: WorkspaceAddInput!) {
    workspaceAdd(input: $input) {
      id
    }
  }
`;

// Same bound as the platform when a cluster is added to an investigation
export const GRAPH_INVESTIGATION_MAX_ELEMENTS = 2000;

/**
 * Start a new investigation with graph analytics results (paths, similar entities and their evidence) and open it.
 * Nothing is written to the knowledge: the investigation only references existing entities and relationships.
 */
const useGraphAnalyticsInvestigation = () => {
  const navigate = useNavigate();
  const [commit, inFlight] = useApiMutation<useGraphAnalyticsInvestigationMutation>(startInvestigationMutation);
  const startInvestigation = (name: string, ids: string[], pivot: GraphAnalyticsPivotKind) => {
    const uniqueIds = Array.from(new Set(ids)).slice(0, GRAPH_INVESTIGATION_MAX_ELEMENTS);
    commit({
      variables: { input: { type: 'investigation', name, investigated_entities_ids: uniqueIds } },
      onCompleted: (response) => {
        recordGraphAnalyticsPivot(pivot);
        if (response.workspaceAdd?.id) {
          navigate(`/dashboard/workspaces/investigations/${response.workspaceAdd.id}`);
        }
      },
    });
  };
  return { startInvestigation, inFlight };
};

export default useGraphAnalyticsInvestigation;
