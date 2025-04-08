import { graphql } from 'react-relay';
import useApiMutation from '../../../utils/hooks/useApiMutation';
import { useKnowledgeGraphDeleteRelationMutation } from './__generated__/useKnowledgeGraphDeleteRelationMutation.graphql';

const knowledgeGraphRelationDelete = graphql`
  mutation useKnowledgeGraphDeleteRelationMutation($id: ID!) {
    stixRelationshipEdit(id: $id) {
      delete
    }
  }
`;

const useKnowledgeGraphDeleteRelation = () => {
  return useApiMutation<useKnowledgeGraphDeleteRelationMutation>(
    knowledgeGraphRelationDelete,
  );
};

export default useKnowledgeGraphDeleteRelation;
