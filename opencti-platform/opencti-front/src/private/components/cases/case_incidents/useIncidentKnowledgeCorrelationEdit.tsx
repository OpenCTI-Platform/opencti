import { graphql } from 'react-relay';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { useIncidentKnowledgeCorrelationEditMutation } from './__generated__/useIncidentKnowledgeCorrelationEditMutation.graphql';

const incidentKnowledgeCorrelationEdit = graphql`
  mutation useIncidentKnowledgeCorrelationEditMutation(
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

const useIncidentKnowledgeCorrelationEdit = () => {
  return useApiMutation<useIncidentKnowledgeCorrelationEditMutation>(
    incidentKnowledgeCorrelationEdit,
  );
};

export default useIncidentKnowledgeCorrelationEdit;
