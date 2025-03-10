import { graphql } from 'react-relay';
import useApiMutation from '../../hooks/useApiMutation';
import { useKnowledgeGraphDeleteObjectMutation } from './__generated__/useKnowledgeGraphDeleteObjectMutation.graphql';

const knowledgeGraphDeleteObject = graphql`
  mutation useKnowledgeGraphDeleteObjectMutation($id: ID!) {
    stixCoreObjectEdit(id: $id) {
      delete
    }
  }
`;

const useKnowledgeGraphDeleteObject = () => {
  return useApiMutation<useKnowledgeGraphDeleteObjectMutation>(
    knowledgeGraphDeleteObject,
  );
};

export default useKnowledgeGraphDeleteObject;
