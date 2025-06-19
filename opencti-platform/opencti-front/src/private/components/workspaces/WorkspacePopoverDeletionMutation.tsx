import { graphql } from 'react-relay';

const WorkspacePopoverDeletionMutation = graphql`
    mutation WorkspacePopoverDeletionMutation($id: ID!) {
        workspaceDelete(id: $id)
    }
`;

export default WorkspacePopoverDeletionMutation;
