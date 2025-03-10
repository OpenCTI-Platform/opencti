import { graphql } from 'react-relay';
import { useGroupingKnowledgeGraphEditMutation } from '@components/analyses/groupings/__generated__/useGroupingKnowledgeGraphEditMutation.graphql';
import useApiMutation from '../../../../utils/hooks/useApiMutation';

const groupingKnowledgeGraphEdit = graphql`
  mutation useGroupingKnowledgeGraphEditMutation($id: ID!, $input: [EditInput]!) {
    groupingFieldPatch(id: $id, input: $input) {
      id
    }
  }
`;

const useGroupingKnowledgeGraphEdit = () => {
  return useApiMutation<useGroupingKnowledgeGraphEditMutation>(
    groupingKnowledgeGraphEdit,
  );
};

export default useGroupingKnowledgeGraphEdit;
