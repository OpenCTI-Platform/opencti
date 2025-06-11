import { graphql } from 'react-relay';

const WorkspaceEditionQuery = graphql`
    query WorkspacePopoverContainerQuery($id: String!) {
        workspace(id: $id) {
            ...WorkspaceEditionContainer_workspace
        }
    }
`;

export default WorkspaceEditionQuery;
