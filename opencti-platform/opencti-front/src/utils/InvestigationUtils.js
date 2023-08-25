import { graphql } from 'react-relay';
import { commitMutation } from '../relay/environment';

const investigationAddFromContainerMutation = graphql`
    mutation InvestigationUtilsInvestigationAddFromContainerMutation($id: ID!) {
        containerEdit(id: $id) {
            investigationAdd {
                id
            }
        }
    }
`;

const investigationAddFromContainer = (groupingId, history) => {
  commitMutation({
    mutation: investigationAddFromContainerMutation,
    variables: { id: groupingId },
    onCompleted: (data) => {
      history.push(`/dashboard/workspaces/investigations/${data.containerEdit.investigationAdd.id}`);
    },
  });
};

export default investigationAddFromContainer;
