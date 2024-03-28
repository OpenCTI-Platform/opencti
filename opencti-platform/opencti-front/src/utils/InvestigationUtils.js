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

const investigationAddFromContainer = (groupingId, navigate) => {
  commitMutation({
    mutation: investigationAddFromContainerMutation,
    variables: { id: groupingId },
    onCompleted: (data) => {
      navigate(`/dashboard/workspaces/investigations/${data.containerEdit.investigationAdd.id}`);
    },
  });
};

export default investigationAddFromContainer;
