import { graphql } from 'react-relay';
import { commitMutation } from '../relay/environment';
import { resolveLink } from './Entity';

const investigationToContainerMutation = graphql`
    mutation ContainerUtilsInvestigationToReportMutation($containerId: ID!, $workspaceId: ID!) {
      containerEdit(id: $containerId) {
        knowledgeAddFromInvestigation(workspaceId: $workspaceId) {
          id
          entity_type
        }
      }
    }
`;

const investigationToContainerAdd = (workspaceId, containerId, history) => {
  commitMutation({
    mutation: investigationToContainerMutation,
    variables: { containerId, workspaceId },
    onCompleted: (data) => {
      const { id, entity_type } = data.containerEdit.knowledgeAddFromInvestigation;
      history.push(`${resolveLink(entity_type.toString())}/${id}/knowledge/graph`);
    },
  });
};

export default investigationToContainerAdd;
