import { graphql } from 'react-relay';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { useReportKnowledgeCorrelationEditMutation } from './__generated__/useReportKnowledgeCorrelationEditMutation.graphql';

const reportKnowledgeCorrelationEdit = graphql`
  mutation useReportKnowledgeCorrelationEditMutation($id: ID!, $input: [EditInput]!) {
    reportEdit(id: $id) {
      fieldPatch(input: $input) {
        id
      }
    }
  }
`;

const useReportKnowledgeCorrelationEdit = () => {
  return useApiMutation<useReportKnowledgeCorrelationEditMutation>(
    reportKnowledgeCorrelationEdit,
  );
};

export default useReportKnowledgeCorrelationEdit;
