import { graphql } from 'react-relay';

const WorkspacePopoverContainerQuery = graphql`
    query WorkspacePopoverContainerQuery($id: String!) {
        workspace(id: $id) {
            ...WorkspaceEditionContainer_workspace
        }
    }
`;

export default WorkspacePopoverContainerQuery;
