import Workflow from './workflow/Workflow';
import { ReactFlowProvider } from 'reactflow';
import { ErrorBoundary } from '../../Error';
import { graphql } from 'react-relay';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { SubTypeWorkflowQuery } from './__generated__/SubTypeWorkflowQuery.graphql';
import Loader from '../../../../components/Loader';
import { Suspense } from 'react';

export const workflowQuery = graphql`
  query SubTypeWorkflowQuery($entityType: String!, $allowDraft: Boolean) {
    workflowDefinition(entityType: $entityType, allowDraft: $allowDraft) {
      id
      name
      published
      errors {
        type
        message
        path {
          id
          entity_type
        }
      }
      initialState
      states {
        statusId
        onExit{
          type
          mode
          params
        }
        onEnter {
          type
          mode
          params
        }
      }
      transitions {
        event
        from
        to
        actions {
          type
          mode
          params
        }
        asyncActions {
          type
          mode
          params
        }
        syncActions {
          type
          mode
          params
        }
        requiresOrganizationInput
        conditions
        comment
      }
    }
    members(search: "", first: 100) {
      edges {
        node {
          id
          entity_type
          name
        }
      }
    }
    organizations(search: "", first: 200) {
      edges {
        node {
          id
          name
        }
      }
    }
    statusTemplates(search: "") {
      edges {
        node {
          id
          name
          color
        }
      }
    }
  }
`;

const SubTypeWorkflow = () => {
  const workflowQueryRef = useQueryLoading<SubTypeWorkflowQuery>(
    workflowQuery,
    { entityType: 'DraftWorkspace', allowDraft: true },
  );

  if (!workflowQueryRef) {
    return <Loader />;
  }

  return (
    <Suspense fallback={<Loader />}>
      <ErrorBoundary>
        <div style={{ width: '100%', height: 'calc(100vh - 250px)', marginBottom: '-50px' }}>
          <ReactFlowProvider>
            <Workflow
              queryRef={workflowQueryRef}
            />
          </ReactFlowProvider>
        </div>
      </ErrorBoundary>
    </Suspense>
  );
};

export default SubTypeWorkflow;
