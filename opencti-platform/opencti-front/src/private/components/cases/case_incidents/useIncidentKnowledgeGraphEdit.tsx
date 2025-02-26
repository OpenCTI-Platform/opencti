import { graphql } from 'react-relay';
import { useIncidentKnowledgeGraphEditMutation } from './__generated__/useIncidentKnowledgeGraphEditMutation.graphql';
import useApiMutation from '../../../../utils/hooks/useApiMutation';

const incidentKnowledgeGraphEdit = graphql`
  mutation useIncidentKnowledgeGraphEditMutation(
    $id: ID! 
    $input: [EditInput]!
    $commitMessage: String
    $references: [String]
  ) {
    stixDomainObjectEdit(id: $id) {
      fieldPatch(
        input: $input
        commitMessage: $commitMessage
        references: $references
      ) {
        id
      }
    }
  }
`;

const useIncidentKnowledgeGraphEdit = () => {
  return useApiMutation<useIncidentKnowledgeGraphEditMutation>(
    incidentKnowledgeGraphEdit,
  );
};

export default useIncidentKnowledgeGraphEdit;
