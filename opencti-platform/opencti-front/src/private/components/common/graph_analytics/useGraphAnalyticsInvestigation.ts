import { graphql } from 'react-relay';
import { useNavigate } from 'react-router';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { useFormatter } from '../../../../components/i18n';
import { MESSAGING$ } from '../../../../relay/environment';
import type { useGraphAnalyticsInvestigationMutation } from './__generated__/useGraphAnalyticsInvestigationMutation.graphql';
import { type GraphAnalyticsPivotKind, recordGraphAnalyticsPivot, reportPayloadErrors } from './graphAnalyticsUtils';

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
 * A result larger than an investigation can start with is refused with a message, never cut.
 */
const useGraphAnalyticsInvestigation = () => {
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const [commit, inFlight] = useApiMutation<useGraphAnalyticsInvestigationMutation>(startInvestigationMutation);
  const startInvestigation = (name: string, ids: string[], pivot: GraphAnalyticsPivotKind) => {
    const uniqueIds = Array.from(new Set(ids));
    if (uniqueIds.length > GRAPH_INVESTIGATION_MAX_ELEMENTS) {
      MESSAGING$.notifyError(t_i18n('This result holds {count, number} elements, more than the {max, number} an investigation can start with. Narrow it, then start the investigation again.', {
        values: { count: uniqueIds.length, max: GRAPH_INVESTIGATION_MAX_ELEMENTS },
      }));
      return;
    }
    commit({
      variables: { input: { type: 'investigation', name, investigated_entities_ids: uniqueIds } },
      onCompleted: (response, errors) => {
        if (reportPayloadErrors(errors) || !response.workspaceAdd?.id) return;
        recordGraphAnalyticsPivot(pivot);
        navigate(`/dashboard/workspaces/investigations/${response.workspaceAdd.id}`);
      },
    });
  };
  return { startInvestigation, inFlight };
};

export default useGraphAnalyticsInvestigation;
