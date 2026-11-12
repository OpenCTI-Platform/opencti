import { graphql } from 'react-relay';
import { useNavigate } from 'react-router';
import useApiMutation from '../../../utils/hooks/useApiMutation';
import useGranted, { INVESTIGATION_INUPDATE } from '../../../utils/hooks/useGranted';
import useDraftContext from '../../../utils/hooks/useDraftContext';
import { MESSAGING$ } from '../../../relay/environment';
import { useFormatter } from '../../i18n';
import type { useGraphStartInvestigationMutation } from './__generated__/useGraphStartInvestigationMutation.graphql';

const graphStartInvestigationMutation = graphql`
  mutation useGraphStartInvestigationMutation($input: WorkspaceAddInput!) {
    workspaceAdd(input: $input) {
      id
    }
  }
`;

/**
 * Starts an investigation seeded with entities of a graph and opens it, the way containers start
 * one from their header. `null` when the user may not create investigations or works in a draft.
 */
const useGraphStartInvestigation = (): ((name: string, entityIds: string[]) => void) | null => {
  const navigate = useNavigate();
  const { t_i18n } = useFormatter();
  const canInvestigate = useGranted([INVESTIGATION_INUPDATE]);
  const draftContext = useDraftContext();
  const [commit] = useApiMutation<useGraphStartInvestigationMutation>(graphStartInvestigationMutation);
  if (!canInvestigate || draftContext) return null;
  return (name, entityIds) => {
    // The platform takes an investigation name of two characters at least: a shorter one is prefixed with the type.
    const trimmed = name.trim();
    const investigationName = trimmed.length >= 2 ? trimmed : `${t_i18n('entity_Investigation')} ${trimmed}`.trim();
    commit({
      variables: { input: { type: 'investigation', name: investigationName, investigated_entities_ids: entityIds } },
      onCompleted: (response, errors) => {
        if (errors && errors.length > 0) {
          MESSAGING$.notifyError(errors[0].message);
          return;
        }
        const id = response.workspaceAdd?.id;
        if (id) navigate(`/dashboard/workspaces/investigations/${id}`);
      },
    });
  };
};

export default useGraphStartInvestigation;
