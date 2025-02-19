import { graphql } from 'react-relay';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { useReportKnowledgeGraphEditMutation } from './__generated__/useReportKnowledgeGraphEditMutation.graphql';

const reportKnowledgeGraphEdit = graphql`
  mutation useReportKnowledgeGraphEditMutation($id: ID!, $input: [EditInput]!) {
    reportEdit(id: $id) {
      fieldPatch(input: $input) {
        ...ReportKnowledgeGraph_fragment
      }
    }
  }
`;

const useReportKnowledgeGraphEdit = () => {
  return useApiMutation<useReportKnowledgeGraphEditMutation>(
    reportKnowledgeGraphEdit,
  );
};

export default useReportKnowledgeGraphEdit;
