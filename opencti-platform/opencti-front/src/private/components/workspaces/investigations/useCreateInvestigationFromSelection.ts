import { useCallback } from 'react';
import { graphql } from 'react-relay';
import { useNavigate } from 'react-router-dom';
import { handleError } from '../../../../relay/environment';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { useCreateInvestigationFromSelectionMutation } from './__generated__/useCreateInvestigationFromSelectionMutation.graphql';

const createInvestigationMutation = graphql`
  mutation useCreateInvestigationFromSelectionMutation($input: WorkspaceAddInput!) {
    workspaceAdd(input: $input) {
      id
    }
  }
`;

const useCreateInvestigationFromSelection = () => {
  const navigate = useNavigate();
  const [commitMutation, creating] = useApiMutation<useCreateInvestigationFromSelectionMutation>(
    createInvestigationMutation,
  );

  const createInvestigation = useCallback((entityIds: string[]) => {
    commitMutation({
      variables: {
        input: {
          type: 'investigation',
          name: `Investigation ${new Date().toISOString()}`,
          investigated_entities_ids: entityIds,
          refresh_interval: null,
        },
      },
      onCompleted: (data) => {
        const investigationId = data.workspaceAdd?.id;
        if (investigationId) {
          navigate(`/dashboard/workspaces/investigations/${investigationId}`);
        }
      },
      onError: handleError,
    });
  }, [commitMutation, navigate]);

  return { createInvestigation, creating };
};

export default useCreateInvestigationFromSelection;
